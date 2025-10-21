#!/usr/bin/env python3
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info
import os, time, random

# --- CLEANUP SECTION (kept small and safe) ---
info("🧹 Pre-test cleanup (logs + mn state)...\n")
os.system("sudo rm -f /tmp/honeypot_logs/event_*.json")
os.system("sudo rm -f /tmp/honeypot_log.txt")
os.system("sudo rm -f /home/sandeep/Capstone_Phase3/controller/risk_mitigation_actions.json")
os.system("sudo rm -rf /home/sandeep/Capstone_Phase3/mininet/test_logs/*")
os.system("sudo mn -c")
info("✅ Cleanup complete.\n")
# ------------------------

# Toggle for reproducible runs (set True to remove randomness)
DETERMINISTIC = False
if DETERMINISTIC:
    random.seed(42)

class SimplifiedTest2VariantTopo(Topo):
    def build(self):
        # Switches (OpenFlow 1.3)
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')

        # Hosts (roles unchanged)
        h1 = self.addHost('h1', ip='10.0.0.1/24')  # Normal user (noisy bursts)
        h2 = self.addHost('h2', ip='10.0.0.2/24')  # Web server (also noisy)
        h3 = self.addHost('h3', ip='10.0.0.3/24')  # Low-risk tester
        h4 = self.addHost('h4', ip='10.0.0.4/24')  # Medium-risk tester
        h5 = self.addHost('h5', ip='10.0.0.5/24')  # High-risk attacker
        h6 = self.addHost('h6', ip='10.0.0.6/24')  # Multi-stage attacker
        h7 = self.addHost('h7', ip='10.0.0.7/24')  # Whitelist candidate (mild misbehave sometimes)
        h8 = self.addHost('h8', ip='10.0.0.8/24')  # Blacklist candidate
        h9 = self.addHost('h9', ip='10.0.0.9/24')  # Honeypot

        # Host-to-switch links
        for h, s in [(h1, s1), (h2, s1), (h3, s2), (h4, s2),
                     (h5, s3), (h6, s3), (h7, s1), (h8, s2), (h9, s3)]:
            self.addLink(h, s, cls=TCLink, bw=10)

        # Inter-switch links
        self.addLink(s1, s2, bw=20)
        self.addLink(s2, s3, bw=20)


def start_services(net):
    info("🔧 Starting simple web and dummy services on h1,h2...\n")
    h1, h2 = net.get('h1', 'h2')
    # both hosts run similar small services
    for host in (h1, h2):
        host.cmd("python3 -m http.server 8080 &")
        host.cmd("python3 -m http.server 8081 &")
        host.cmd("nc -l -p 2222 &")
        host.cmd("nc -l -p 3306 &")
    time.sleep(1)
    info("✅ Services started on h1 and h2.\n")


def start_honeypot_service(h9):
    """Start honeypot on h9 and create a log file."""
    info("🐝 Starting honeypot on h9 (port 2222)...\n")
    h9.cmd("mkdir -p /tmp/honeypot_logs >/dev/null 2>&1")
    h9.cmd("touch /tmp/honeypot_log.txt")
    # Make sure the honeypot_server.py exists in working dir; if not, create a tiny fallback listener
    if os.path.exists("honeypot_server.py"):
        h9.cmd("python3 honeypot_server.py > /tmp/honeypot_log.txt 2>&1 &")
    else:
        # fallback: simple netcat listener to generate connection logs
        h9.cmd("bash -c 'while true; do nc -l -p 2222 -e /bin/cat >> /tmp/honeypot_log.txt; done' &")
    time.sleep(1)
    info("✅ Honeypot started (check /tmp/honeypot_log.txt on h9)\n")


def jitter_sleep(base=1.0, jitter=0.5):
    """Sleep with optional randomness unless deterministic mode is set."""
    if DETERMINISTIC or jitter <= 0:
        time.sleep(base)
    else:
        time.sleep(base + random.uniform(-jitter, jitter))


def noisy_burst(host, target_ip, intensity=5, short_pause=0.4):
    """Generate small noisy background traffic from legit hosts to create ambiguity."""
    for _ in range(intensity):
        host.cmd(f"curl -s --connect-timeout 1 http://{target_ip}:8080/ > /dev/null 2>&1 &")
        time.sleep(short_pause)


def simulate_attack(host, target_ip, attack_type):
    """Attack simulator with slight randomness and varied intensity."""
    if attack_type == "dns_spoof":
        # single dig + short pings (less deterministic)
        host.cmd(f"dig @8.8.8.8 fakebank.com > /dev/null 2>&1 &")
        for _ in range(random.randint(5, 10) if not DETERMINISTIC else 8):
            host.cmd(f"ping -c1 {target_ip} > /dev/null 2>&1")
            jitter_sleep(0.4, 0.2)

    elif attack_type == "arp_spoof":
        # run arpspoof for a variable duration
        host.cmd(f"arpspoof -t {target_ip} 10.0.0.1 > /dev/null 2>&1 &")
        jitter_sleep(3.0, 1.0)
        host.cmd("pkill arpspoof || true")

    elif attack_type == "brute_force":
        # varied intensity brute force (some shorter, some longer)
        attempts = random.randint(20, 50) if not DETERMINISTIC else 30
        for _ in range(attempts):
            host.cmd(f"nc {target_ip} 22 < /dev/null > /dev/null 2>&1 &")
            jitter_sleep(0.05, 0.03)
        jitter_sleep(2.0, 0.5)

    elif attack_type == "scan":
        # scan smaller or larger range randomly
        if not DETERMINISTIC and random.random() < 0.4:
            host.cmd(f"nmap -T4 -p 1-512 {target_ip} > /dev/null 2>&1 &")
        else:
            host.cmd(f"nmap -T4 -p 1-1024 {target_ip} > /dev/null 2>&1 &")
        jitter_sleep(3.0, 1.5)
        host.cmd("pkill nmap || true")

    elif attack_type == "honeypot_probe":
        attempts = 3 if DETERMINISTIC else random.randint(3, 8)
        for _ in range(attempts):
            host.cmd(f"nc -w 1 {target_ip} 2222 < /dev/null > /dev/null 2>&1")
            jitter_sleep(0.2, 0.1)

    elif attack_type == "benign":
        # standard low-rate traffic
        for _ in range(5):
            host.cmd(f"curl -s http://{target_ip}:8080 > /dev/null 2>&1")
            jitter_sleep(1.5, 0.4)


def run_tests(net):
    info("\n🚀 Starting Test 2 (variant — introduces noise & timing overlap)\n")
    h1,h2,h3,h4,h5,h6,h7,h8,h9 = net.get('h1','h2','h3','h4','h5','h6','h7','h8','h9')

    start_services(net)
    start_honeypot_service(h9)

    # start small background noisy bursts from legit hosts to create ambiguity
    info("🟢 Starting background noisy bursts from h1,h2,h7 (makes detection slightly harder)\n")
    for host in (h1, h2, h7):
        # run bursts in background so they overlap with attacks
        host.cmd("bash -c 'for i in {1..6}; do curl -s http://10.0.0.2:8080 >/dev/null 2>&1; sleep 1; done' &")
    jitter_sleep(1.0, 0.5)

    # 1) h5 starts ARP spoofing and shorter brute force (but repeated later)
    info("🔴 h5 begins ARP spoofing + intermittent brute-force\n")
    simulate_attack(h5, h2.IP(), "arp_spoof")
    simulate_attack(h5, h2.IP(), "brute_force")

    # small delay with jitter (overlap -> ambiguity)
    jitter_sleep(1.5, 1.0)

    # 2) h6 performs lighter brute-force but also probes honeypot later (multistage)
    info("💀 h6 performing light brute-force and later honeypot probe\n")
    simulate_attack(h6, h2.IP(), "brute_force")
    jitter_sleep(0.5, 0.3)

    # 3) h8 performs DNS spoof + honeypot probing (clear attacker)
    info("⚫ h8 launching DNS spoof + honeypot probe\n")
    simulate_attack(h8, h2.IP(), "dns_spoof")
    simulate_attack(h8, h9.IP(), "honeypot_probe")

    # 4) medium scanner h4 (timed to overlap with h5/h6)
    jitter_sleep(0.2, 0.15)
    info("🟡 h4 running medium scan\n")
    simulate_attack(h4, h2.IP(), "scan")

    # 5) occasional legitimate ping traffic from h1/h3 for baseline
    info("🔎 Generating baseline benign pings from h1,h3\n")
    for host in (h1, h3):
        host.cmd(f"ping -c3 {h2.IP()} > /dev/null 2>&1 &")

    # 6) Whitelisted candidate h7 does a small suspicious curl burst (creates potential FP)
    if not DETERMINISTIC and random.random() < 0.5:
        info("⚠️ h7 (usually benign) sends a short burst (creates ambiguity)\n")
        simulate_attack(h7, h2.IP(), "benign")

    # 7) Attackers contact honeypot at the end to ensure honeypot logging
    jitter_sleep(1.0, 0.7)
    info("🧠 h5 and h8 will probe honeypot to generate tripwire events\n")
    simulate_attack(h5, h9.IP(), "honeypot_probe")
    simulate_attack(h8, h9.IP(), "honeypot_probe")

    # show honeypot tail
    info("\n📄 Honeypot recent activity (tail):\n")
    info(h9.cmd("tail -n 20 /tmp/honeypot_log.txt"))
    info("\n✅ Test 2 variant complete — check controller logs for more ambiguous outcomes.\n")


def run_network():
    topo = SimplifiedTest2VariantTopo()
    net = Mininet(topo=topo, controller=None, switch=OVSKernelSwitch, link=TCLink)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    net.start()
    info("🌐 Network up — running Test 2 variant\n")

    run_tests(net)
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run_network()
