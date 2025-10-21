from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info
import os, time, random

# --- CLEANUP SECTION ---
info("🧹 Cleaning up old logs and Mininet state...\n")
os.system("sudo rm -f /tmp/honeypot_logs/event_*.json")
os.system("sudo rm -f /tmp/honeypot_log.txt")
os.system("sudo rm -f /home/sandeep/Capstone_Phase3/controller/risk_mitigation_actions.json")
os.system("sudo rm -rf /home/sandeep/Capstone_Phase3/mininet/test_logs/*")
os.system("sudo mn -c")
info("✅ Cleanup complete. Environment ready.\n")
# ------------------------

class SimplifiedTest2Topo(Topo):
    def build(self):
        # Switches (OpenFlow 1.3)
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')

        # Hosts (same roles)
        h1 = self.addHost('h1', ip='10.0.0.1/24')  # Normal user
        h2 = self.addHost('h2', ip='10.0.0.2/24')  # Web server
        h3 = self.addHost('h3', ip='10.0.0.3/24')  # Low-risk tester
        h4 = self.addHost('h4', ip='10.0.0.4/24')  # Medium-risk tester
        h5 = self.addHost('h5', ip='10.0.0.5/24')  # High-risk attacker
        h6 = self.addHost('h6', ip='10.0.0.6/24')  # Multi-stage attacker
        h7 = self.addHost('h7', ip='10.0.0.7/24')  # Whitelist candidate
        h8 = self.addHost('h8', ip='10.0.0.8/24')  # Blacklist candidate
        h9 = self.addHost('h9', ip='10.0.0.9/24')  # Honeypot

        # Links
        for h, s in [(h1, s1), (h2, s1), (h3, s2), (h4, s2),
                     (h5, s3), (h6, s3), (h7, s1), (h8, s2), (h9, s3)]:
            self.addLink(h, s, cls=TCLink, bw=10)

        # Inter-switch links
        self.addLink(s1, s2, bw=20)
        self.addLink(s2, s3, bw=20)


def start_services(net):
    info("🔧 Starting web and dummy services...\n")
    h1, h2 = net.get('h1', 'h2')
    for cmd in [
        "python3 -m http.server 8080 &",
        "python3 -m http.server 8081 &",
        "nc -l -p 2222 &",
        "nc -l -p 3306 &"
    ]:
        h1.cmd(cmd)
        h2.cmd(cmd)
    info("✅ Services up\n")


def start_honeypot_service(h9):
    """Start the honeypot service on h9."""
    info("🧠 Launching honeypot on h9...\n")
    # Create simple honeypot log if not present
    h9.cmd("touch /tmp/honeypot_log.txt")
    
    # Start your honeypot server (make sure honeypot_server.py exists in Mininet dir)
    h9.cmd("python3 honeypot_server.py > /tmp/honeypot_log.txt 2>&1 &")
    time.sleep(2)
    
    # Verify it’s running
    check = h9.cmd("ps aux | grep honeypot_server.py | grep -v grep")
    if check:
        info("✅ Honeypot running on port 2222\n")
    else:
        info("⚠️ Honeypot failed to start\n")


def simulate_attack(host, target_ip, attack_type):
    """Simulate attacks and benign traffic."""
    if attack_type == "dns_spoof":
        host.cmd(f"dig @8.8.8.8 fakebank.com > /dev/null 2>&1 &")
        for _ in range(10):
            host.cmd(f"ping -c1 {target_ip} > /dev/null 2>&1")
            time.sleep(0.5)
    elif attack_type == "arp_spoof":
        host.cmd(f"arpspoof -t {target_ip} 10.0.0.1 > /dev/null 2>&1 &")
        time.sleep(5)
        host.cmd("pkill arpspoof")
    elif attack_type == "brute_force":
        for _ in range(30):
            host.cmd(f"nc {target_ip} 22 < /dev/null > /dev/null 2>&1 &")
        time.sleep(3)
    elif attack_type == "scan":
        host.cmd(f"nmap -T4 -p 1-1024 {target_ip} > /dev/null 2>&1 &")
        time.sleep(4)
        host.cmd("pkill nmap")
    elif attack_type == "honeypot_probe":
        for _ in range(5):
            host.cmd(f"nc -w 1 {target_ip} 2222 < /dev/null > /dev/null 2>&1")
            time.sleep(0.2)
    elif attack_type == "benign":
        for _ in range(5):
            host.cmd(f"curl -s http://{target_ip}:8080 > /dev/null 2>&1")
            time.sleep(2)


def run_tests(net):
    info("\n🚀 Starting SDN Mitigation Test 2 (with Honeypot)\n")
    h1,h2,h3,h4,h5,h6,h7,h8,h9 = net.get('h1','h2','h3','h4','h5','h6','h7','h8','h9')
    start_services(net)
    start_honeypot_service(h9)

    # 1️⃣ Normal background traffic
    info("🟢 Normal user traffic (h1,h3 → h2)\n")
    for h in [h1, h3]:
        h.cmd(f"ping -c3 {h2.IP()} > /dev/null 2>&1 &")

    # 2️⃣ ARP spoofing and Brute Force attack from h5
    info("🔴 h5 performing ARP spoofing\n")
    simulate_attack(h5, h2.IP(), "arp_spoof")
    simulate_attack(h5, h2.IP(), "brute_force")

    # 3️⃣ Brute-force SSH simulation from h6
    info("💀 h6 brute-force simulation\n")
    simulate_attack(h6, h2.IP(), "brute_force")

    # 4️⃣ DNS spoofing attempt by h8
    info("⚫ h8 launching DNS spoof\n")
    simulate_attack(h8, h2.IP(), "dns_spoof")

    # 5️⃣ Honeypot probing from h5 and h8
    info("🧠 h5 and h8 contacting honeypot (h9)\n")
    simulate_attack(h5, h9.IP(), "honeypot_probe")
    simulate_attack(h8, h9.IP(), "honeypot_probe")

    # 6️⃣ Port scanning by h4
    info("🟡 h4 running medium scan\n")
    simulate_attack(h4, h2.IP(), "scan")

    # 7️⃣ Whitelisted h7 sending benign traffic
    info("🟢 Whitelisted h7 normal behavior\n")
    simulate_attack(h7, h2.IP(), "benign")

    info("📄 Checking honeypot logs on h9:\n")
    info(h9.cmd("tail -n 10 /tmp/honeypot_log.txt"))
    info("✅ Test 2 complete — analyze controller logs for response.\n")


def run_network():
    topo = SimplifiedTest2Topo()
    net = Mininet(topo=topo, controller=None, switch=OVSKernelSwitch, link=TCLink)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    net.start()
    info("🌐 Network ready for Test 2 with Honeypot\n")

    run_tests(net)
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run_network()
