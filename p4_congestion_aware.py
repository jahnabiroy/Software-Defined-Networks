import logging
from logging.handlers import RotatingFileHandler
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.topology import event, switches
from ryu.topology.api import *
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from time import sleep, time
from ryu.lib.packet import ether_types
import heapq
from ryu.lib.packet import lldp
from ryu.lib import hub

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.host_to_switch = {}
        self.forwarding_table = {}
        self.host_to_port = {}
        self.blocked_ports = {}
        self.mac_on_switches = {}
        self.link_delay = {}
        self.link = {}
        self.spanning_tree_table = {}
        self.switch_ids = set()
        self.switch_to_datapath = {}
        self.switches = []
        self.alpha = 0.125
        # Set up logging to a file
        log_file = "p4.log"
        # clean_log_file(log_file)
        with open(log_file, "w"):
            pass

        self.logger.propagate = False
        if self.logger.hasHandlers():
            self.logger.handlers.clear()

        handler = RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5
        )
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        hub.spawn(self.read_topology)  # Start the periodic execution

    def read_topology(self):
        hub.sleep(100)  # Wait for 100 seconds before the next call
        while True:
            self.read_topology()
            hub.sleep(100)  # Wait for 100 seconds before the next call
        

    def clear_data(self):
        self.host_to_switch.clear()
        self.forwarding_table.clear()
        self.host_to_port.clear()
        self.blocked_ports.clear()
        self.mac_on_switches.clear()
        self.spanning_tree_table.clear()
        self.switch_ids.clear()
        self.switch_to_datapath.clear()
        self.switches.clear()

    def send_lldp_packets(self):
        # self.logger.info("Started sending lldp packets")
        for dpid in self.switch_ids:
            # self.logger.info("Start sending on switch %s", dpid)
            datapath = self.switch_to_datapath.get(dpid, None)
            if datapath is not None:
                pkt = packet.Packet()
                eth = ethernet.ethernet(
                    dst=lldp.LLDP_MAC_NEAREST_BRIDGE,
                    src=datapath.ports[datapath.ofproto.OFPP_LOCAL].hw_addr,
                    ethertype=ether_types.ETH_TYPE_LLDP,
                )
                sending_time = time()
                chassis_id = lldp.ChassisID(
                    subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
                    chassis_id=(f"Link_Delay::{dpid}::{sending_time}").encode("utf-8"),
                )
                port_id = lldp.PortID(
                    subtype=lldp.PortID.SUB_LOCALLY_ASSIGNED,
                    port_id=str(datapath.id).encode("utf-8"),
                )
                ttl = lldp.TTL(ttl=13)
                lldp_pkt = lldp.lldp([chassis_id, port_id, ttl])
                pkt.add_protocol(eth)
                pkt.add_protocol(lldp_pkt)
                pkt.serialize()
                actions = [
                    datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)
                ]
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                    in_port=datapath.ofproto.OFPP_CONTROLLER,
                    actions=actions,
                    data=pkt.data,
                )
                datapath.send_msg(out)
        # self.logger.info("Ended sending lldp packets")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match, instructions=inst
            )

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            lldp_pkt = pkt.get_protocol(lldp.lldp)
            chassis_id = None
            for tlv in lldp_pkt.tlvs:
                if isinstance(tlv, lldp.ChassisID):
                    # Extract and decode the ChassisID
                    chassis_id = tlv.chassis_id.decode("utf-8")
                    break
            if chassis_id is not None:
                if "::" not in chassis_id:
                    self.link.setdefault(dpid, {})
                    self.link[dpid][int(chassis_id[5:])] = in_port
                    return
                # self.logger.info("Chassis Id: %s", chassis_id)
                parts = chassis_id.split("::")
                if len(parts) != 3:  # Ensure there are exactly two parts
                    return
                try:
                    part1 = parts[0]  # Attempt to convert the first part to an integer
                    part2 = int(parts[1])
                    send_time = float(parts[2])
                except ValueError as e:
                    self.logger.info("Error: %s", e)
                    return  # If conversion fails, exit the function
                if part1 == "Link_Delay":
                    current_time = time()
                    link_delay = current_time - send_time
                    # self.logger.info("Switch %s to %s : %s", dpid, part2, link_delay * 1000)
                    self.link_delay.setdefault(dpid, {})
                    self.link_delay.setdefault(part2, {})
                    current1 = self.link_delay[dpid].get(part2, float("inf"))
                    current2 = self.link_delay[part2].get(dpid, float("inf"))
                    self.link.setdefault(dpid, {})
                    self.link[dpid][part2] = in_port
                    self.link_delay[dpid][part2] = 1000*link_delay if current1 == float("inf") else self.alpha*current1 + (1-self.alpha)*link_delay * 1000
                    self.link_delay[part2][dpid] = 1000*link_delay if current1 == float("inf") else self.alpha*current2 + (1-self.alpha)*link_delay * 1000
                    
                    if current1 == float("inf") or current2 == float("inf"):
                        self.construct_forwarding_table()

            return

        out_port = ofproto.OFPP_FLOOD
        self.forwarding_table.setdefault(dpid, {})
        self.forwarding_table[dpid][src] = in_port
        if dst in self.forwarding_table[dpid]:
            out_port = self.forwarding_table[dpid][dst]

        # if dst != "ff:ff:ff:ff:ff:ff" and dst != "33:33:00:00:00:02":
        #     self.logger.info("DPID: %s, Destination: %s, Source: %s, Out Port: %s, In Port: %s", dpid, dst, src, out_port, in_port)

        actions = []
        if out_port != ofproto.OFPP_FLOOD:
            actions = [parser.OFPActionOutput(out_port)]
        else:
            ports = [port.port_no for port in datapath.ports.values()]
            for port in ports:
                if port != in_port and port not in self.blocked_ports.get(dpid, set()):
                    actions.append(parser.OFPActionOutput(port))

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
            return

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data,
        )
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev=None):
        sleep(0.1)
        switch_list = get_switch(self.topology_api_app, None)
        self.switches = [switch.dp.id for switch in switch_list]
        self.switch_to_datapath = {switch.dp.id: switch.dp for switch in switch_list}
        links_list = get_all_link(self.topology_api_app)
        self.switch_ids = set(self.switches)

        for l in links_list:
            self.link.setdefault(l.src.dpid, {})
            self.link.setdefault(l.dst.dpid, {})
            self.link_delay.setdefault(l.src.dpid, {})
            self.link_delay.setdefault(l.dst.dpid, {})
            self.link[l.src.dpid][l.dst.dpid] = l.src.port_no
            self.link[l.dst.dpid][l.src.dpid] = l.dst.port_no
            self.mac_on_switches.setdefault(l.src.dpid, set())
            self.mac_on_switches.setdefault(l.dst.dpid, set())
            self.mac_on_switches[l.src.dpid].add(l.src.hw_addr)
            self.mac_on_switches[l.dst.dpid].add(l.dst.hw_addr)

        # self.logger.info("Switches %s", self.switches)
        # self.logger.info("Inside Topo Links: %s", self.link)
        if self.switches:
            self.send_lldp_packets()
        else:
            print("No switches discovered yet. Spanning tree creation deferred.")

    def find_spt_edges(self):
        edges = []
        connected_switches = set()
        if not self.switch_ids:
            return {}
        start_switch = next(iter(self.switch_ids))
        connected_switches.add(start_switch)
        while len(connected_switches) < len(self.switch_ids):
            new_edges = []
            for switch in list(connected_switches):
                for neighbor, port in self.link.get(switch, {}).items():
                    if neighbor not in connected_switches:
                        new_edges.append((switch, neighbor))
            if not new_edges:
                break
            edges.append(new_edges[0])
            connected_switches.add(new_edges[0][1])
            connected_switches.add(new_edges[0][0])
        spt_edges = {}
        for edge in edges:
            spt_edges.setdefault(edge[0], {})
            spt_edges.setdefault(edge[1], {})
            if edge[1] not in self.link[edge[0]]:
                continue
            if edge[0] not in self.link[edge[1]]:
                continue
            spt_edges[edge[0]][edge[1]] = self.link[edge[0]][edge[1]]
            spt_edges[edge[1]][edge[0]] = self.link[edge[1]][edge[0]]

        return spt_edges

    def construct_forwarding_table(self):
        self.forwarding_table = {switch: {} for switch in self.switch_ids}
        self.spanning_tree_table = {switch: {} for switch in self.switch_ids}
        for switch in self.link:
            for neighbor in self.link[switch]:
                self.link_delay.setdefault(switch, {})
                self.link_delay.setdefault(neighbor, {})
                delay1 = self.link_delay[switch].get(neighbor, float("inf"))
                delay2 = self.link_delay[neighbor].get(switch, float("inf"))
                self.link_delay[switch][neighbor] = min(delay1, delay2)
                self.link_delay[neighbor][switch] = min(delay1, delay2)

        def dijkstra(start):
            distance = {node: float("inf") for node in self.switch_ids}
            distance[start] = 0
            visited = {}
            previous_nodes = {}
            priority_queue = [(0, start)]  # Initialize the priority queue
            ports = {}

            while priority_queue:
                current_distance, current_node = heapq.heappop(priority_queue)

                if current_node in visited:
                    continue
                visited[current_node] = current_distance
                for neighbor in self.link_delay.get(current_node, {}):
                    if neighbor in visited:
                        continue
                    weight = self.link_delay[current_node].get(neighbor, float("inf"))
                    new_distance = current_distance + weight
                    self.link.setdefault(current_node, {})
                    # self.link[current_node].setdefault(neighbor,0)
                    if new_distance < distance.get(neighbor, float("inf")):
                        distance[neighbor] = new_distance
                        previous_nodes[neighbor] = current_node
                        ports[neighbor] = ports.get(
                            current_node,
                            self.link[current_node].get(neighbor, 4294967294),
                        )
                        heapq.heappush(priority_queue, (new_distance, neighbor))

            # self.logger.info("Start: %s",start)
            # self.logger.info("Ports: %s",ports)
            # self.logger.info("Distances: %s",distance)
            return ports

        def bfs(node, parent, original_switch, original_port, visited, spt_edges):
            if visited[node]:
                return
            visited[node] = True
            for neighbor in spt_edges[node]:
                if neighbor != parent:
                    self.spanning_tree_table[original_switch][neighbor] = original_port
                    bfs(
                        neighbor,
                        node,
                        original_switch,
                        original_port,
                        visited,
                        spt_edges,
                    )

        for switch in self.switch_ids:
            self.forwarding_table[switch] = dijkstra(switch)

        spt_edges = self.find_spt_edges()
        # self.logger.info("SPT Edges: %s",spt_edges)
        for switch in spt_edges:
            visited = {sw: False for sw in self.switch_ids}
            for neighbor in spt_edges[switch]:
                port = self.link[switch][neighbor]
                self.spanning_tree_table[switch][neighbor] = port
                bfs(neighbor, switch, switch, port, visited, spt_edges)

        for switch in self.link:
            datapath = self.switch_to_datapath[switch]
            self.blocked_ports[switch] = set()  # Corrected to reassign to an empty set
            # self.logger.info("Switch %s: %s",switch,datapath.ports.values())
            for port in datapath.ports.values():
                if port.port_no in self.spanning_tree_table.get(switch, {}).values():
                    continue
                if port.port_no not in self.link.get(switch, {}).values():
                    continue
                self.blocked_ports.setdefault(switch, set()).add(port.port_no)  
        # self.logger.info("Constructed Forwarding Table")
        # self.logger.info("Links: %s", self.link)
        # self.logger.info("Forwarding Table: %s", self.forwarding_table)
        # self.logger.info("Spanning Table: %s", self.spanning_tree_table)
        # self.logger.info("Blocked Ports: %s", self.blocked_ports)
        # self.logger.info("Mac on switches: %s", self.mac_on_switches)
