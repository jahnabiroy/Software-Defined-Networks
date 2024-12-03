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
from ryu.lib.packet import ipv6  # Add this line
from time import sleep
from ryu.lib.packet import ether_types

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.ports_on_switch = {}
        self.host_to_switch = {}
        self.spanning_tree = []
        self.forwarding_table = {}
        self.host_to_port = {}
        self.blocked_ports = {}
        # Set up logging to a file
        log_file = "p2.log"
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
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)

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
            return

        out_port = ofproto.OFPP_FLOOD
        if dst in self.forwarding_table[dpid]:
            out_port = self.forwarding_table[dpid][dst]

        # if out_port != ofproto.OFPP_FLOOD:
        #     self.logger.info("DPID: %s, Destination: %s, Source: %s, Out Port: %s, In Port: %s", dpid, dst, src, out_port, in_port)

        actions = []
        if out_port != ofproto.OFPP_FLOOD:
            actions = [parser.OFPActionOutput(out_port)]
        else:
            ports = [port.port_no for port in datapath.ports.values()]
            for port in ports:
                if port != in_port and port not in self.blocked_ports.get(dpid, []):
                    actions.append(parser.OFPActionOutput(port))

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src = src ,eth_dst=dst)
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
        links_list = get_all_link(self.topology_api_app)
        self.links = {}
        self.switch_ids = set()
        for l in links_list:
            self.switch_ids.add(l.src.dpid)
            self.switch_ids.add(l.dst.dpid)
            if l.src.dpid not in self.links:
                self.links[l.src.dpid] = {}
            if l.dst.dpid not in self.links:
                self.links[l.dst.dpid] = {}
            self.links[l.src.dpid][l.dst.dpid] = l.src.port_no
            self.links[l.dst.dpid][l.src.dpid] = l.dst.port_no

        if self.switch_ids:
            self.create_spanning_tree()
        else:
            print("No switches discovered yet. Spanning tree creation deferred.")
        
        # self.get_topology_data(self.topology_api_app)

    def create_spanning_tree(self):
        if not self.switch_ids:
            self.logger.warning("No switches to create spanning tree.")
            return

        spt_edges = self.find_spt_edges()
        self.construct_spt_and_forwarding_table(spt_edges)

    def find_spt_edges(self):
        edges = []
        connected_switches = set()

        start_switch = next(iter(self.switch_ids))
        connected_switches.add(start_switch)

        while len(connected_switches) < len(self.switch_ids):
            new_edges = []
            for switch in list(
                connected_switches
            ):  
                for neighbor, port in self.links.get(switch, {}).items():
                    if neighbor not in connected_switches:
                        new_edges.append((switch, neighbor))
                    

            if not new_edges:
                break

            edges.append(new_edges[0])
            connected_switches.add(new_edges[0][1])
            connected_switches.add(new_edges[0][0])

        spt_edges = {}
        for edge in edges:
            if edge[0] not in spt_edges:
                spt_edges[edge[0]] = {}
            if edge[1] not in spt_edges:
                spt_edges[edge[1]] = {}

            spt_edges[edge[0]][edge[1]] = self.links[edge[0]][edge[1]]
            spt_edges[edge[1]][edge[0]] = self.links[edge[1]][edge[0]]

        return spt_edges

    def construct_spt_and_forwarding_table(self, spt_edges):
        self.spanning_tree = spt_edges
        self.forwarding_table = {switch: {} for switch in self.switch_ids}

        def bfs(node, parent, original_switch, original_port, visited):
            if visited[node]:
                return
            visited[node] = True
            for neighbor in spt_edges[node]:
                if neighbor != parent:
                    self.forwarding_table[original_switch][neighbor] = original_port
                    bfs(neighbor, node, original_switch, original_port, visited)

        for switch in self.switch_ids:
            visited = {sw: False for sw in self.switch_ids}
            for neighbor in spt_edges[switch]:
                port = self.links[switch][neighbor]
                self.forwarding_table[switch][neighbor] = port
                bfs(neighbor, switch, switch, port, visited)

        for switch in self.switch_ids:
            self.ports_on_switch[switch] = list(
                set(self.forwarding_table[switch].values())
            )
        
        for switch1 in self.switch_ids:
            for switch2 in self.links[switch1]:
                if self.links[switch1][switch2] != self.forwarding_table[switch1][switch2]:
                    self.blocked_ports.setdefault(switch1, set()).add(self.links[switch1][switch2])
                    self.blocked_ports.setdefault(switch2, set()).add(self.links[switch2][switch1])

        # self.logger.info("Ports on each switch: %s", self.ports_on_switch)
        # self.logger.info("Forwarding Table: %s", self.forwarding_table)
        # self.logger.info("Blocked Ports: %s", self.blocked_ports)