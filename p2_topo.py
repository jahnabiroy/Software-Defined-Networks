#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.log import setLogLevel, info
from mininet.cli import CLI

class CustomTopo(Topo):
    """Custom topology with 4 switches forming a cycle and 1 host per switch."""

    def build(self):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        # Create 4 hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        # Connect each host to its respective switch
        self.addLink(h1, s1)
        self.addLink(h2, s2)
        self.addLink(h3, s3)
        self.addLink(h4, s4)

        # Connect switches to form a cycle
        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s4)
        self.addLink(s4, s1)

def construct_spanning_tree(topo):
    """Construct a spanning tree from the given topology using Prim's algorithm."""
    nodes = list(topo.nodes())
    edges = list(topo.links())
    if not nodes:
        return []

    # Initialize the spanning tree with the first node
    spanning_tree = []
    connected_nodes = {nodes[0]}
    remaining_nodes = set(nodes[1:])

    while remaining_nodes:
        min_edge = None
        for edge in edges:
            if (edge[0] in connected_nodes and edge[1] in remaining_nodes) or \
               (edge[1] in connected_nodes and edge[0] in remaining_nodes):
                if min_edge is None or edge < min_edge:
                    min_edge = edge

        if min_edge is None:
            raise ValueError("The graph is not connected")

        spanning_tree.append(min_edge)
        connected_nodes.update(min_edge)
        remaining_nodes.difference_update(min_edge)

    return spanning_tree

def run():
    """Create the network, start it, and enter the CLI."""
    topo = CustomTopo()
    net = Mininet(topo=topo, switch=OVSSwitch, build=False)
    net.addController('c0', controller=RemoteController, ip="127.0.0.1", protocol='tcp', port=6633)
    net.build()
    net.start()

    # Construct the spanning tree
    spanning_tree = construct_spanning_tree(topo)
    info('*** Spanning Tree:\n')
    for edge in spanning_tree:
        info(f'{edge}\n')

    # Save the spanning tree to a file for the controller to read
    with open('/tmp/spanning_tree.txt', 'w') as f:
        for edge in spanning_tree:
            f.write(f'{edge[0]} {edge[1]}\n')

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    # Set log level to display Mininet output
    setLogLevel('info')
    run()
