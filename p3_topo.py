from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import OVSSwitch, RemoteController
class CustomTopo(Topo):
    def build(self):
        # Add four nodes (hosts)
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        # Add links with specified capacities
        self.addLink(h1, h2, bw=200)  # 200 Mbps link
        self.addLink(h2, h3, bw=200)  # 200 Mbps link
        self.addLink(h3, h4, bw=200)  # 200 Mbps link
        self.addLink(h4, h1, bw=100)  # 100 Mbps link

def run():
    topo = CustomTopo()
    net = Mininet(topo=topo, link=TCLink, switch=OVSSwitch, build=False)  # Use TCLink for bandwidth limitations
    net.addController('c0', controller=RemoteController, ip="127.0.0.1", protocol='tcp', port=6633)
    net.build()
    net.start()

    # Start CLI for further testing
    CLI(net)

    # Stop the network
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
