#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.topo import Topo
from mininet.cli import CLI


class CustomTopo(Topo):
    def build(self):
        # Create four switches
        s1 = self.addSwitch("s1", protocols="OpenFlow13")
        s2 = self.addSwitch("s2", protocols="OpenFlow13")
        s3 = self.addSwitch("s3", protocols="OpenFlow13")
        s4 = self.addSwitch("s4", protocols="OpenFlow13")

        # Create four hosts, one for each switch
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        h3 = self.addHost("h3")
        h4 = self.addHost("h4")

        # Add links between hosts and their respective switches
        self.addLink(h1, s1)
        self.addLink(h2, s2)
        self.addLink(h3, s3)
        self.addLink(h4, s4)

        # Add links between switches in a cycle with 20 Mbps bandwidth
        self.addLink(s1, s2, bw=2, delay="20ms", cls=TCLink)
        self.addLink(s2, s3, bw=2, delay="10ms", cls=TCLink)
        self.addLink(s3, s4, bw=1, delay="20ms", cls=TCLink)
        self.addLink(s4, s1, bw=1, delay="15ms", cls=TCLink)


def run():
    # Initialize the network with the custom topology
    topo = CustomTopo()
    # Notice: Do not specify a controller here. We'll add it later.
    net = Mininet(
        topo=topo, link=TCLink, switch=OVSKernelSwitch, controller=None, build=False
    )

    # Build and start the topology without connecting to any controller
    net.build()
    net.start()

    # After the network is started, connect to the remote controller
    controller = net.addController(
        "c0", controller=RemoteController, ip="127.0.0.1", port=6633
    )

    # Reconnect all switches to the remote controller
    for switch in net.switches:
        switch.start([controller])

    # Drop the user into the CLI for testing
    CLI(net)

    # Stop the network after exiting the CLI
    net.stop()


if __name__ == "__main__":
    run()
