#!/usr/bin/env python3
"""
Synthetic Test Data Generator

This module generates realistic synthetic log data for testing the mitigation system
when real network traffic logs are not available. It creates comprehensive test
scenarios covering all security decision types and edge cases.

Generated Data Types:
1. Risk Mitigation Actions - Various security decisions with different risk levels
2. Anomaly Detection Events - ML-based threat detection with varying confidence scores
3. Realistic Network Patterns - Simulates actual network behavior and attack scenarios

Author: Network Security Team
Version: 1.0
Date: 2025
"""

import json
import random
from datetime import datetime, timedelta
import ipaddress
from collections import defaultdict

class SyntheticDataGenerator:
    """
    Generates realistic synthetic data for comprehensive mitigation system testing.
    
    This class creates test scenarios that cover all aspects of the security system
    including normal traffic, various attack patterns, and edge cases to ensure
    thorough validation of the mitigation accuracy.
    """
    
    def __init__(self):
        """Initialize the synthetic data generator"""
        self.base_time = datetime.now() - timedelta(hours=2)  # Start 2 hours ago
        
        # Network topology for realistic IP generation
        self.legitimate_ips = [
            '10.0.0.1', '10.0.0.2', '10.0.0.3',  # Normal hosts
            '192.168.1.10', '192.168.1.20'       # Additional legitimate sources
        ]
        
        self.suspicious_ips = [
            '172.16.0.100', '203.0.113.50',      # External suspicious sources  
            '198.51.100.75', '192.0.2.200'       # Known bad actor patterns
        ]
        
        self.honeypot_ips = ['10.0.0.9', '10.0.0.10']  # Configured honeypots
        
        # Risk thresholds matching the system configuration
        self.low_risk_threshold = 0.08
        self.medium_risk_threshold = 0.18
        self.high_risk_threshold = 0.25
        
        print("🤖 Synthetic Data Generator Initialized")
        print(f"   Legitimate IPs: {len(self.legitimate_ips)}")
        print(f"   Suspicious IPs: {len(self.suspicious_ips)}")
        print(f"   Honeypot IPs: {self.honeypot_ips}")

    def generate_comprehensive_test_data(self):
        """Generate comprehensive synthetic test data covering all scenarios"""
        
        print("\n📊 Generating Comprehensive Test Scenarios...")
        
        # Generate different types of test data
        risk_actions = []
        anomaly_events = []
        
        # Scenario 1: Normal legitimate traffic (should be ALLOWED)
        legitimate_data = self._generate_legitimate_traffic_scenarios()
        risk_actions.extend(legitimate_data['risk_actions'])
        anomaly_events.extend(legitimate_data['anomaly_events'])
        
        # Scenario 2: Low-risk suspicious activity (should be ALLOWED with monitoring)
        low_risk_data = self._generate_low_risk_scenarios()
        risk_actions.extend(low_risk_data['risk_actions'])
        anomaly_events.extend(low_risk_data['anomaly_events'])
        
        # Scenario 3: Medium-risk threats (should be RATE_LIMITED)
        medium_risk_data = self._generate_medium_risk_scenarios()
        risk_actions.extend(medium_risk_data['risk_actions'])
        anomaly_events.extend(medium_risk_data['anomaly_events'])
        
        # Scenario 4: High-risk attacks (should be BLOCKED)
        high_risk_data = self._generate_high_risk_scenarios()
        risk_actions.extend(high_risk_data['risk_actions'])
        anomaly_events.extend(high_risk_data['anomaly_events'])
        
        # Scenario 5: Honeypot access attempts (should be immediately BLOCKED)
        honeypot_data = self._generate_honeypot_scenarios()
        risk_actions.extend(honeypot_data['risk_actions'])
        anomaly_events.extend(honeypot_data['anomaly_events'])
        
        # Scenario 6: Blacklist/Whitelist scenarios
        policy_data = self._generate_policy_scenarios()
        risk_actions.extend(policy_data['risk_actions'])
        anomaly_events.extend(policy_data['anomaly_events'])
        
        # Sort by timestamp for realistic chronological order
        risk_actions.sort(key=lambda x: x['timestamp'])
        anomaly_events.sort(key=lambda x: x['timestamp'])
        
        # Save synthetic data to files
        self._save_risk_actions(risk_actions)
        self._save_anomaly_events(anomaly_events)
        
        print(f"✅ Generated {len(risk_actions)} risk mitigation actions")
        print(f"✅ Generated {len(anomaly_events)} anomaly detection events")
        print("📁 Saved to: ../risk_mitigation_actions.json and ../anomaly_log.json")

    def _generate_legitimate_traffic_scenarios(self):
        """Generate normal legitimate traffic that should be allowed"""
        
        risk_actions = []
        anomaly_events = []
        
        for i in range(50):  # 50 legitimate flows
            source_ip = random.choice(self.legitimate_ips)
            timestamp = self._get_incremental_timestamp()
            
            # Low risk score for legitimate traffic
            risk_score = random.uniform(0.01, self.low_risk_threshold - 0.01)
            ml_confidence = random.uniform(0.01, 0.05)
            
            # Risk action entry
            risk_action = {
                'action_type': 'ALLOW',
                'source_ip': source_ip,
                'timestamp': timestamp,
                'risk_score': risk_score,
                'risk_level': 'LOW',
                'details': 'Legitimate traffic allowed with continued monitoring',
                'packet_count': random.randint(10, 100),
                'byte_count': random.randint(800, 8000)
            }
            risk_actions.append(risk_action)
            
            # Corresponding anomaly event (low confidence, not detected as anomaly)
            if random.random() < 0.3:  # Only 30% of legitimate traffic generates anomaly logs
                anomaly_event = {
                    'timestamp': timestamp,
                    'confidence': ml_confidence,
                    'flow_info': {
                        'protocol': random.choice(['tcp', 'udp']),
                        'src_ip': source_ip,
                        'dst_ip': random.choice(self.legitimate_ips),
                        'src_port': random.randint(1024, 65535),
                        'dst_port': random.choice([80, 443, 22, 53])
                    },
                    'statistics': {
                        'duration': random.randint(1, 30),
                        'packets': risk_action['packet_count'],
                        'bytes': risk_action['byte_count']
                    }
                }
                anomaly_events.append(anomaly_event)
        
        return {'risk_actions': risk_actions, 'anomaly_events': anomaly_events}

    def _generate_low_risk_scenarios(self):
        """Generate low-risk suspicious activity"""
        
        risk_actions = []
        anomaly_events = []
        
        for i in range(30):  # 30 low-risk flows
            source_ip = random.choice(self.suspicious_ips + self.legitimate_ips)
            timestamp = self._get_incremental_timestamp()
            
            # Low-medium risk score
            risk_score = random.uniform(self.low_risk_threshold, self.medium_risk_threshold - 0.02)
            ml_confidence = random.uniform(0.05, 0.15)
            
            # Could be ALLOW or RATE_LIMIT depending on exact score
            action_type = 'ALLOW' if risk_score < 0.12 else 'RATE_LIMIT'
            risk_level = 'LOW' if risk_score < 0.12 else 'MEDIUM'
            
            risk_action = {
                'action_type': action_type,
                'source_ip': source_ip,
                'timestamp': timestamp,
                'risk_score': risk_score,
                'risk_level': risk_level,
                'details': f'Low-medium risk traffic {action_type.lower()}ed',
                'packet_count': random.randint(50, 200),
                'byte_count': random.randint(2000, 16000)
            }
            
            if action_type == 'RATE_LIMIT':
                risk_action['pps_limit'] = random.randint(500, 800)
                risk_action['bps_limit'] = random.randint(500000, 800000)
            
            risk_actions.append(risk_action)
            
            # Higher chance of anomaly detection for suspicious traffic
            if random.random() < 0.7:  # 70% chance
                anomaly_event = {
                    'timestamp': timestamp,
                    'confidence': ml_confidence,
                    'flow_info': {
                        'protocol': random.choice(['tcp', 'udp', 'icmp']),
                        'src_ip': source_ip,
                        'dst_ip': random.choice(self.legitimate_ips),
                        'src_port': random.randint(1024, 65535),
                        'dst_port': random.choice([80, 443, 22, 23, 21, 25])
                    },
                    'statistics': {
                        'duration': random.randint(1, 10),
                        'packets': risk_action['packet_count'],
                        'bytes': risk_action['byte_count']
                    }
                }
                anomaly_events.append(anomaly_event)
        
        return {'risk_actions': risk_actions, 'anomaly_events': anomaly_events}

    def _generate_medium_risk_scenarios(self):
        """Generate medium-risk threats that should be rate limited"""
        
        risk_actions = []
        anomaly_events = []
        
        for i in range(25):  # 25 medium-risk flows
            source_ip = random.choice(self.suspicious_ips)
            timestamp = self._get_incremental_timestamp()
            
            # Medium risk score
            risk_score = random.uniform(self.medium_risk_threshold, self.high_risk_threshold - 0.02)
            ml_confidence = random.uniform(0.15, 0.23)
            
            risk_action = {
                'action_type': 'RATE_LIMIT',
                'source_ip': source_ip,
                'timestamp': timestamp,
                'risk_score': risk_score,
                'risk_level': 'MEDIUM',
                'details': 'Medium risk traffic rate limited based on risk assessment',
                'packet_count': random.randint(200, 500),
                'byte_count': random.randint(10000, 40000),
                'pps_limit': random.randint(200, 500),
                'bps_limit': random.randint(200000, 500000),
                'rate_multiplier': random.uniform(0.3, 0.6)
            }
            risk_actions.append(risk_action)
            
            # Anomaly detection should catch most medium-risk traffic
            if random.random() < 0.9:  # 90% detection rate
                anomaly_event = {
                    'timestamp': timestamp,
                    'confidence': ml_confidence,
                    'flow_info': {
                        'protocol': random.choice(['tcp', 'udp']),
                        'src_ip': source_ip,
                        'dst_ip': random.choice(self.legitimate_ips),
                        'src_port': random.randint(1024, 65535),
                        'dst_port': random.choice([80, 443, 22, 21, 25, 135, 139, 445])
                    },
                    'statistics': {
                        'duration': random.randint(1, 5),
                        'packets': risk_action['packet_count'],
                        'bytes': risk_action['byte_count']
                    }
                }
                anomaly_events.append(anomaly_event)
        
        return {'risk_actions': risk_actions, 'anomaly_events': anomaly_events}

    def _generate_high_risk_scenarios(self):
        """Generate high-risk attacks that should be blocked"""
        
        risk_actions = []
        anomaly_events = []
        
        for i in range(20):  # 20 high-risk flows
            source_ip = random.choice(self.suspicious_ips)
            timestamp = self._get_incremental_timestamp()
            
            # High/Critical risk score
            risk_score = random.uniform(self.high_risk_threshold, 0.95)
            ml_confidence = random.uniform(0.25, 0.9)
            
            # Determine timeout duration based on risk
            timeout_duration = int(60 * (risk_score * 3))  # 60s to 3min based on risk
            
            risk_level = 'HIGH' if risk_score < 0.5 else 'CRITICAL'
            
            risk_action = {
                'action_type': 'SHORT_TIMEOUT_BLOCK',
                'source_ip': source_ip,
                'timestamp': timestamp,
                'risk_score': risk_score,
                'risk_level': risk_level,
                'details': f'High risk traffic blocked for {timeout_duration}s with blacklist escalation',
                'packet_count': random.randint(500, 2000),
                'byte_count': random.randint(20000, 100000),
                'timeout_duration': timeout_duration,
                'incident_type': 'HIGH_RISK_BLOCK'
            }
            risk_actions.append(risk_action)
            
            # High-risk traffic should always be detected
            anomaly_event = {
                'timestamp': timestamp,
                'confidence': ml_confidence,
                'flow_info': {
                    'protocol': random.choice(['tcp', 'udp', 'icmp']),
                    'src_ip': source_ip,
                    'dst_ip': random.choice(self.legitimate_ips),
                    'src_port': random.randint(1024, 65535),
                    'dst_port': random.choice([22, 23, 21, 135, 139, 445, 3389, 1433])  # Attack ports
                },
                'statistics': {
                    'duration': random.randint(1, 3),
                    'packets': risk_action['packet_count'],
                    'bytes': risk_action['byte_count']
                }
            }
            anomaly_events.append(anomaly_event)
        
        return {'risk_actions': risk_actions, 'anomaly_events': anomaly_events}

    def _generate_honeypot_scenarios(self):
        """Generate honeypot access attempts (should trigger maximum response)"""
        
        risk_actions = []
        anomaly_events = []
        
        for i in range(10):  # 10 honeypot access attempts
            source_ip = random.choice(self.suspicious_ips)
            honeypot_ip = random.choice(self.honeypot_ips)
            timestamp = self._get_incremental_timestamp()
            
            # Maximum risk score for honeypot hits
            risk_score = 1.0
            ml_confidence = random.uniform(0.1, 0.9)  # Even low ML confidence should trigger max response
            
            risk_action = {
                'action_type': 'SHORT_TIMEOUT_BLOCK',
                'source_ip': source_ip,
                'timestamp': timestamp,
                'risk_score': risk_score,
                'risk_level': 'CRITICAL',
                'details': f'HONEYPOT ACCESS DETECTED - Immediate blocking for {3600}s with blacklist escalation',
                'packet_count': random.randint(5, 50),
                'byte_count': random.randint(200, 2000),
                'timeout_duration': 3600,  # Maximum timeout
                'incident_type': 'HONEYPOT_TRIPWIRE',
                'is_honeypot_hit': True
            }
            risk_actions.append(risk_action)
            
            # Honeypot access always generates detection event
            anomaly_event = {
                'timestamp': timestamp,
                'confidence': ml_confidence,
                'flow_info': {
                    'protocol': random.choice(['tcp', 'udp']),
                    'src_ip': source_ip,
                    'dst_ip': honeypot_ip,
                    'src_port': random.randint(1024, 65535),
                    'dst_port': random.choice([22, 23, 21, 80, 443, 25])
                },
                'statistics': {
                    'duration': random.randint(1, 2),
                    'packets': risk_action['packet_count'],
                    'bytes': risk_action['byte_count']
                }
            }
            anomaly_events.append(anomaly_event)
        
        return {'risk_actions': risk_actions, 'anomaly_events': anomaly_events}

    def _generate_policy_scenarios(self):
        """Generate blacklist/whitelist policy scenarios"""
        
        risk_actions = []
        anomaly_events = []
        
        # Whitelisted traffic (should always be allowed)
        for i in range(15):  # 15 whitelisted flows
            source_ip = random.choice(self.legitimate_ips)
            timestamp = self._get_incremental_timestamp()
            
            # Even if ML detects as suspicious, whitelist should override
            risk_score = random.uniform(0.05, 0.3)
            ml_confidence = random.uniform(0.05, 0.25)
            
            risk_action = {
                'action_type': 'ALLOW',
                'source_ip': source_ip,
                'timestamp': timestamp,
                'risk_score': risk_score,
                'risk_level': 'LOW',
                'details': 'Whitelisted source - traffic allowed regardless of risk score',
                'packet_count': random.randint(20, 150),
                'byte_count': random.randint(1000, 12000),
                'whitelist_override': True
            }
            risk_actions.append(risk_action)
        
        # Previously blacklisted sources (action depends on ML confidence)
        for i in range(10):  # 10 blacklisted attempts
            source_ip = random.choice(self.suspicious_ips)
            timestamp = self._get_incremental_timestamp()
            
            # Blacklisted IPs get reputation boost, final action depends on total risk score
            ml_confidence = random.uniform(0.1, 0.6)
            # Risk calculation: (ml_confidence * 0.7) + (blacklist_boost * 0.1)
            blacklist_boost = 0.2  # Blacklisted IPs get ~0.02 reputation factor
            total_risk = (ml_confidence * 0.7) + blacklist_boost
            
            if total_risk >= 0.25:
                action_type = 'SHORT_TIMEOUT_BLOCK'
                risk_level = 'CRITICAL'
                details = 'Blacklisted source with high ML confidence - critical risk blocking'
                timeout_duration = random.randint(300, 1800)
            else:
                action_type = 'REDIRECT_TO_HONEYPOT'
                risk_level = 'HIGH'
                details = 'Blacklisted source redirected to honeypot for analysis'
                timeout_duration = None
            
            risk_action = {
                'action_type': action_type,
                'source_ip': source_ip,
                'timestamp': timestamp,
                'risk_score': total_risk,
                'risk_level': risk_level,
                'details': details,
                'packet_count': random.randint(1, 10),
                'byte_count': random.randint(50, 500),
                'blacklist_hit': True
            }
            
            if timeout_duration:
                risk_action['timeout_duration'] = timeout_duration
            risk_actions.append(risk_action)
        
        return {'risk_actions': risk_actions, 'anomaly_events': anomaly_events}

    def _get_incremental_timestamp(self):
        """Get incrementally advancing timestamp for realistic chronology"""
        timestamp = self.base_time + timedelta(seconds=random.randint(1, 30))
        self.base_time = timestamp  # Advance base time
        return timestamp.isoformat()

    def _save_risk_actions(self, risk_actions):
        """Save risk mitigation actions to JSON file"""
        with open('../risk_mitigation_actions.json', 'w') as f:
            for action in risk_actions:
                json.dump(action, f)
                f.write('\n')

    def _save_anomaly_events(self, anomaly_events):
        """Save anomaly detection events to JSON file"""
        with open('../anomaly_log.json', 'w') as f:
            for event in anomaly_events:
                json.dump(event, f)
                f.write('\n')

    def generate_stress_test_data(self):
        """Generate large-scale stress test data for performance validation"""
        
        print("\n🚀 Generating Stress Test Dataset...")
        
        risk_actions = []
        anomaly_events = []
        
        # Generate 1000 entries for stress testing
        for i in range(1000):
            source_ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
            timestamp = self._get_incremental_timestamp()
            
            # Random risk distribution
            risk_score = random.random()
            ml_confidence = random.uniform(0.01, 0.95)
            
            # Determine action based on risk
            if risk_score < self.low_risk_threshold:
                action_type, risk_level = 'ALLOW', 'LOW'
            elif risk_score < self.medium_risk_threshold:
                action_type, risk_level = 'RATE_LIMIT', 'MEDIUM'
            else:
                action_type, risk_level = 'SHORT_TIMEOUT_BLOCK', 'HIGH'
            
            risk_action = {
                'action_type': action_type,
                'source_ip': source_ip,
                'timestamp': timestamp,
                'risk_score': risk_score,
                'risk_level': risk_level,
                'details': f'Stress test entry {i+1}',
                'packet_count': random.randint(1, 1000),
                'byte_count': random.randint(64, 65536)
            }
            risk_actions.append(risk_action)
        
        self._save_risk_actions(risk_actions)
        print(f"✅ Generated {len(risk_actions)} stress test entries")

def main():
    """Main execution function for standalone testing"""
    
    print("🧪 Synthetic Test Data Generator")
    print("Generating comprehensive test scenarios...")
    print("-" * 50)
    
    generator = SyntheticDataGenerator()
    generator.generate_comprehensive_test_data()
    
    print("\n📊 Test data generation completed!")
    print("Ready for validation testing.")

if __name__ == "__main__":
    main()
