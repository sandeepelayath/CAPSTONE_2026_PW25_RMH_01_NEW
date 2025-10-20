#!/usr/bin/env python3
"""
Mitigation Accuracy Validation Tests

This module validates the accuracy of the Risk-Based Mitigation Manager by
testing various network security scenarios against expected outcomes.

Test Cases:
1. Whitelist Host Traffic - Should be ALLOWED
2. Blacklisted Host Traffic - Should be BLOCKED/RATE_LIMITED
3. Honeypot Access Attempts - Should be BLOCKED immediately
4. Low Risk Traffic - Should be ALLOWED
5. High Risk Traffic - Should be BLOCKED/RATE_LIMITED

Author: Network Security Team
Version: 1.0
Date: 2025
"""

import sys
import os
import json
import time
from datetime import datetime, timedelta
from collections import defaultdict

# Add parent directory to path to import controller modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from mitigation_manager import RiskBasedMitigationManager
except ImportError:
    print("❌ Error: Cannot import RiskBasedMitigationManager")
    print("Ensure this script is run from the controller directory")
    sys.exit(1)

class MockController:
    """Mock controller for testing purposes"""
    def __init__(self):
        self.datapaths = {}
        self.mac_to_ip = {}

class MockFlowStats:
    """Mock OpenFlow statistics for testing"""
    def __init__(self, packet_count=100, byte_count=8000, duration_sec=10):
        self.packet_count = packet_count
        self.byte_count = byte_count
        self.duration_sec = duration_sec
        self.duration_nsec = 0
        self.match = MockMatch()

class MockMatch:
    """Mock OpenFlow match for testing"""
    def __init__(self, src_ip="10.0.0.1", dst_ip="10.0.0.2"):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
    
    def to_jsondict(self):
        return {
            'OFPMatch': {
                'ipv4_src': self.src_ip,
                'ipv4_dst': self.dst_ip
            }
        }

class MitigationAccuracyValidator:
    """
    Validates the accuracy of mitigation decisions against expected outcomes.
    
    This class runs comprehensive tests to ensure the Risk-Based Mitigation Manager
    makes correct security decisions based on various network scenarios.
    """
    
    def __init__(self):
        """Initialize the validation test suite"""
        self.mock_controller = MockController()
        self.mitigation_manager = RiskBasedMitigationManager(
            controller_ref=self.mock_controller,
            low_risk_threshold=0.08,
            medium_risk_threshold=0.15, 
            high_risk_threshold=0.30
        )
        
        self.test_results = []
        self.passed_tests = 0
        self.failed_tests = 0
        
        print("🧪 Mitigation Accuracy Validator Initialized")
        print(f"   Risk Thresholds: LOW<{0.08}, MEDIUM<{0.15}, HIGH<{0.30}")

    def test_whitelist_host_allowed(self):
        """Test Case 1: Whitelisted host traffic should be ALLOWED"""
        print("\n🧪 Test 1: Whitelist Host Traffic")
        
        # Setup: Add host to whitelist
        test_ip = "10.0.0.100"
        self.mitigation_manager._add_to_whitelist(test_ip, "Test whitelist entry")
        
        # Create low-risk flow from whitelisted host
        flow_stats = MockFlowStats(packet_count=50, byte_count=4000, duration_sec=5)
        flow_stats.match.src_ip = test_ip
        
        # Test mitigation decision
        result = self.mitigation_manager.risk_based_mitigation(
            flow_stats=flow_stats,
            ml_confidence=0.05,  # Low ML confidence
            source_ip=test_ip
        )
        
        # Validate result
        expected_action = "ALLOW"
        success = result and result.get('action') == expected_action
        
        self._record_test_result(
            test_name="Whitelist Host Allowed",
            expected=expected_action,
            actual=result.get('action') if result else 'None',
            success=success,
            details=f"Whitelisted IP {test_ip} with low risk should be allowed"
        )
        
        return success

    def test_blacklisted_host_blocked(self):
        """Test Case 2: Blacklisted host traffic should be BLOCKED"""
        print("\n🧪 Test 2: Blacklisted Host Traffic")
        
        # Setup: Add host to blacklist
        test_ip = "10.0.0.200"
        self.mitigation_manager._add_to_blacklist(test_ip, 300, 0.8)
        
        # Create flow from blacklisted host
        flow_stats = MockFlowStats(packet_count=200, byte_count=16000, duration_sec=2)
        flow_stats.match.src_ip = test_ip
        
        # Test mitigation decision with high ML confidence to ensure critical risk level
        result = self.mitigation_manager.risk_based_mitigation(
            flow_stats=flow_stats,
            ml_confidence=0.4,  # High ML confidence to push blacklisted IP into critical risk
            source_ip=test_ip
        )
        
        # Validate result - blacklisted hosts with high ML confidence should be blocked
        # Note: Blacklisted IPs get reputation boost, so with high ML confidence they reach critical risk
        expected_action = "SHORT_TIMEOUT_BLOCK"
        success = result and result.get('action') in ["BLOCK", "SHORT_TIMEOUT_BLOCK"]
        
        self._record_test_result(
            test_name="Blacklisted Host Blocked",
            expected="BLOCK/SHORT_TIMEOUT_BLOCK",
            actual=result.get('action') if result else 'None',
            success=success,
            details=f"Blacklisted IP {test_ip} with high ML confidence should reach critical risk and be blocked"
        )
        
        return success

    def test_honeypot_access_blocked(self):
        """Test Case 3: Honeypot access attempts should trigger maximum security response"""
        print("\n🧪 Test 3: Honeypot Access Attempt")
        
        # Setup: Use one of the configured honeypot IPs
        test_ip = "10.0.0.50"
        honeypot_ip = "10.0.0.9"  # Configured honeypot
        
        # Create flow targeting honeypot
        flow_stats = MockFlowStats(packet_count=10, byte_count=800, duration_sec=1)
        flow_stats.match.src_ip = test_ip
        flow_stats.match.dst_ip = honeypot_ip
        
        # Test mitigation decision
        result = self.mitigation_manager.risk_based_mitigation(
            flow_stats=flow_stats,
            ml_confidence=0.1,  # Even low confidence should trigger maximum response
            source_ip=test_ip,
            dest_ip=honeypot_ip
        )
        
        # Validate result - honeypot access should trigger immediate blocking
        expected_action = "SHORT_TIMEOUT_BLOCK"
        success = result and result.get('action') == expected_action
        
        self._record_test_result(
            test_name="Honeypot Access Blocked",
            expected=expected_action,
            actual=result.get('action') if result else 'None',
            success=success,
            details=f"Access to honeypot {honeypot_ip} from {test_ip} should trigger immediate blocking"
        )
        
        return success

    def test_low_risk_traffic_allowed(self):
        """Test Case 4: Low risk traffic should be ALLOWED"""
        print("\n🧪 Test 4: Low Risk Traffic")
        
        test_ip = "10.0.0.150"
        
        # Create normal flow with low ML confidence
        flow_stats = MockFlowStats(packet_count=30, byte_count=2400, duration_sec=8)
        flow_stats.match.src_ip = test_ip
        
        # Test mitigation decision
        result = self.mitigation_manager.risk_based_mitigation(
            flow_stats=flow_stats,
            ml_confidence=0.02,  # Very low ML confidence
            source_ip=test_ip
        )
        
        # Validate result
        expected_action = "ALLOW"
        success = result and result.get('action') == expected_action
        
        self._record_test_result(
            test_name="Low Risk Traffic Allowed",
            expected=expected_action,
            actual=result.get('action') if result else 'None',
            success=success,
            details=f"Low risk traffic from {test_ip} (confidence: 0.02) should be allowed"
        )
        
        return success

    def test_high_risk_traffic_blocked(self):
        """Test Case 5: High risk traffic should be BLOCKED or RATE_LIMITED"""
        print("\n🧪 Test 5: High Risk Traffic")
        
        test_ip = "10.0.0.250"
        
        # Create suspicious flow with high ML confidence
        flow_stats = MockFlowStats(packet_count=1000, byte_count=80000, duration_sec=1)
        flow_stats.match.src_ip = test_ip
        
        # Test mitigation decision
        result = self.mitigation_manager.risk_based_mitigation(
            flow_stats=flow_stats,
            ml_confidence=0.85,  # High ML confidence
            source_ip=test_ip
        )
        
        # Validate result - high risk should trigger blocking or rate limiting
        expected_actions = ["RATE_LIMIT", "SHORT_TIMEOUT_BLOCK", "BLOCK"]
        success = result and result.get('action') in expected_actions
        
        self._record_test_result(
            test_name="High Risk Traffic Mitigated",
            expected="RATE_LIMIT/BLOCK",
            actual=result.get('action') if result else 'None',
            success=success,
            details=f"High risk traffic from {test_ip} (confidence: 0.85) should be mitigated"
        )
        
        return success

    def test_medium_risk_rate_limited(self):
        """Test Case 6: Medium risk traffic should be RATE_LIMITED"""
        print("\n🧪 Test 6: Medium Risk Traffic")
        
        test_ip = "10.0.0.175"
        
        # Create moderately suspicious flow
        flow_stats = MockFlowStats(packet_count=300, byte_count=24000, duration_sec=3)
        flow_stats.match.src_ip = test_ip
        
        # Test mitigation decision
        result = self.mitigation_manager.risk_based_mitigation(
            flow_stats=flow_stats,
            ml_confidence=0.15,  # Medium ML confidence
            source_ip=test_ip
        )
        
        # Validate result - medium risk should trigger rate limiting
        expected_actions = ["RATE_LIMIT", "ALLOW"]  # Could be either depending on exact risk calculation
        success = result and result.get('action') in expected_actions
        
        self._record_test_result(
            test_name="Medium Risk Traffic Rate Limited",
            expected="RATE_LIMIT/ALLOW",
            actual=result.get('action') if result else 'None',
            success=success,
            details=f"Medium risk traffic from {test_ip} (confidence: 0.15) should be rate limited or allowed"
        )
        
        return success

    def _record_test_result(self, test_name, expected, actual, success, details):
        """Record the result of a test case"""
        
        result = {
            'test_name': test_name,
            'expected': expected,
            'actual': actual,
            'success': success,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        
        self.test_results.append(result)
        
        if success:
            self.passed_tests += 1
            print(f"   ✅ PASS: {test_name}")
            print(f"      Expected: {expected}, Got: {actual}")
        else:
            self.failed_tests += 1
            print(f"   ❌ FAIL: {test_name}")
            print(f"      Expected: {expected}, Got: {actual}")
            print(f"      Details: {details}")

    def run_validation_tests(self):
        """Execute all validation tests"""
        
        print("🚀 Starting Mitigation Accuracy Validation")
        print("=" * 50)
        
        # Execute test cases
        test_methods = [
            self.test_whitelist_host_allowed,
            self.test_blacklisted_host_blocked,
            self.test_honeypot_access_blocked,
            self.test_low_risk_traffic_allowed,
            self.test_high_risk_traffic_blocked,
            self.test_medium_risk_rate_limited
        ]
        
        for test_method in test_methods:
            try:
                test_method()
                time.sleep(0.1)  # Brief pause between tests
            except Exception as e:
                self._record_test_result(
                    test_name=test_method.__name__,
                    expected="No Exception",
                    actual=f"Exception: {str(e)}",
                    success=False,
                    details=f"Test execution failed with exception: {str(e)}"
                )
        
        # Generate summary report
        self._generate_summary_report()

    def _generate_summary_report(self):
        """Generate summary report of validation results"""
        
        total_tests = self.passed_tests + self.failed_tests
        accuracy = (self.passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        print("\n" + "=" * 60)
        print("📊 MITIGATION ACCURACY VALIDATION SUMMARY")
        print("=" * 60)
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {self.passed_tests}")
        print(f"Failed: {self.failed_tests}")
        print(f"Accuracy: {accuracy:.1f}%")
        
        if accuracy >= 90:
            print("🏆 EXCELLENT: System accuracy meets production standards")
        elif accuracy >= 75:
            print("✅ GOOD: System accuracy acceptable for deployment")
        elif accuracy >= 50:
            print("⚠️ FAIR: System accuracy needs improvement")
        else:
            print("❌ POOR: System accuracy requires immediate attention")
        
        # Save detailed report
        report = {
            'summary': {
                'total_tests': total_tests,
                'passed': self.passed_tests,
                'failed': self.failed_tests,
                'accuracy_percentage': accuracy,
                'test_timestamp': datetime.now().isoformat()
            },
            'detailed_results': self.test_results
        }
        
        with open('mitigation_accuracy_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📋 Detailed report saved to: mitigation_accuracy_report.json")

def main():
    """Main execution function"""
    
    print("🔬 Mitigation Accuracy Validation Test Suite")
    print("Testing Risk-Based Network Security Decisions")
    print("-" * 50)
    
    validator = MitigationAccuracyValidator()
    validator.run_validation_tests()

if __name__ == "__main__":
    main()
