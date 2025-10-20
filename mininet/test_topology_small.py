from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time

class SimpleHoneypotTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        h1 = self.addHost('h1', ip='10.0.0.1/24')  # Attacker
        h9 = self.addHost('h9', ip='10.0.0.9/24')  # Honeypot
        self.addLink(h1, s1)
        self.addLink(h9, s1)

def test_honeypot_traffic(net):
    h1 = net.get('h1')
    h9 = net.get('h9')
    info("\n[TEST] Sending traffic from h1 to honeypot (h9:22)\n")
    for i in range(5):
        h1.cmd('nc -w 1 10.0.0.9 22 < /dev/null > /dev/null 2>&1')
        h1.cmd('telnet 10.0.0.9 22 < /dev/null > /dev/null 2>&1')
        time.sleep(0.5)
    info("[TEST] Done sending test traffic.\n")

def start_honeypot_server(net):
    h9 = net.get('h9')
    info("[INFO] Starting honeypot_server.py on h9...\n")
    # Adjust the path if honeypot_server.py is not in the current directory of h9
    h9.cmd('python3 honeypot_server.py &')

def start_network():
    topo = SimpleHoneypotTopo()
    net = Mininet(topo=topo, controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653), switch=OVSKernelSwitch)
    net.start()
    info("\n[INFO] Network started.\n")
    start_honeypot_server(net)
    time.sleep(1)  # Give honeypot server a moment to start
    net.pingAll()
    test_honeypot_traffic(net)
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    start_network()
