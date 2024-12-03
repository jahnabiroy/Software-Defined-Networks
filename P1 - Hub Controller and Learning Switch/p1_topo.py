from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import RemoteController, OVSSwitch

class CustomTopo(Topo):
    def build(self):
        # Add two switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Add hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')

        # Connect hosts to switch S1
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

        # Connect hosts to switch S2
        self.addLink(h4, s2)
        self.addLink(h5, s2)

        # Optionally, add a link between the two switches
        self.addLink(s1, s2)

def run():
    """Create the network, start it, and enter the CLI."""
    topo = CustomTopo()
    net = Mininet(topo=topo, switch=OVSSwitch, build=False)
    net.addController('c0', controller=RemoteController, ip="127.0.0.1", protocol='tcp', port=6633)
    net.build()
    net.start()
    info('*** Running CLI\n')
    CLI(net)


    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    # Set log level to display Mininet output
    setLogLevel('info')
    run()

