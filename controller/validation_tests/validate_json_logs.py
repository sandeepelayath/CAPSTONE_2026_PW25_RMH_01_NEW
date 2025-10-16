#!/usr/bin/env python3
"""
JSON Log Validation Tests

This module validates the integrity and consistency of JSON log files generated
by the Risk-Based Mitigation Manager. It ensures that security decisions are
properly logged and that the log data matches expected patterns.

Validation Areas:
1. Risk Mitigation Actions Log - Validates security decision logging
2. Anomaly Detection Log - Validates ML-based threat detection logging  
3. Cross-Validation - Ensures consistency between logs
4. Data Integrity - Validates JSON structure and required fields

Author: Network Security Team
Version: 1.0
Date: 2025
"""

import json
import os
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import re

class JSONLogValidator:
    """
    Validates JSON log files for data integrity and decision consistency.
    
    This class analyzes log files to ensure proper logging of security decisions
    and validates that the logged actions match expected patterns based on risk scores.
    """
    
    def __init__(self):
        """Initialize the JSON log validator"""
        self.risk_actions_file = '../risk_mitigation_actions.json'
        self.anomaly_log_file = '../anomaly_log.json'
        
        self.validation_results = {
            'risk_actions': {'passed': 0, 'failed': 0, 'issues': []},
            'anomaly_detection': {'passed': 0, 'failed': 0, 'issues': []},
            'cross_validation': {'passed': 0, 'failed': 0, 'issues': []}
        }
        
        print("📋 JSON Log Validator Initialized")
        print(f"   Risk Actions Log: {self.risk_actions_file}")
        print(f"   Anomaly Log: {self.anomaly_log_file}")

    def load_json_logs(self):
        """Load and parse JSON log files"""
        
        logs = {'risk_actions': [], 'anomalies': []}
        
        # Load risk mitigation actions log
        try:
            if os.path.exists(self.risk_actions_file):
                with open(self.risk_actions_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        try:
                            log_entry = json.loads(line.strip())
                            log_entry['_line_number'] = line_num
                            logs['risk_actions'].append(log_entry)
                        except json.JSONDecodeError as e:
                            print(f"⚠️ Invalid JSON in risk actions log, line {line_num}: {e}")
                
                print(f"✅ Loaded {len(logs['risk_actions'])} risk action entries")
            else:
                print(f"⚠️ Risk actions log file not found: {self.risk_actions_file}")
        
        except Exception as e:
            print(f"❌ Error loading risk actions log: {e}")
        
        # Load anomaly detection log
        try:
            if os.path.exists(self.anomaly_log_file):
                with open(self.anomaly_log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        try:
                            log_entry = json.loads(line.strip())
                            log_entry['_line_number'] = line_num
                            logs['anomalies'].append(log_entry)
                        except json.JSONDecodeError as e:
                            print(f"⚠️ Invalid JSON in anomaly log, line {line_num}: {e}")
                
                print(f"✅ Loaded {len(logs['anomalies'])} anomaly detection entries")
            else:
                print(f"⚠️ Anomaly log file not found: {self.anomaly_log_file}")
        
        except Exception as e:
            print(f"❌ Error loading anomaly log: {e}")
        
        return logs

    def validate_risk_actions_log(self, risk_actions):
        """Validate risk mitigation actions log entries"""
        
        print("\n🔍 Validating Risk Mitigation Actions Log")
        print("-" * 45)
        
        required_fields = ['action_type', 'source_ip', 'timestamp', 'risk_score', 'risk_level']
        action_types = ['ALLOW', 'RATE_LIMIT', 'SHORT_TIMEOUT_BLOCK', 'BLOCK']
        risk_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        
        for entry in risk_actions:
            line_num = entry.get('_line_number', 'unknown')
            
            # Test 1: Required fields validation
            missing_fields = [field for field in required_fields if field not in entry]
            if missing_fields:
                self.validation_results['risk_actions']['failed'] += 1
                self.validation_results['risk_actions']['issues'].append(
                    f"Line {line_num}: Missing required fields: {missing_fields}"
                )
                continue
            
            # Test 2: Action type validation
            action_type = entry.get('action_type')
            if action_type not in action_types:
                self.validation_results['risk_actions']['failed'] += 1
                self.validation_results['risk_actions']['issues'].append(
                    f"Line {line_num}: Invalid action_type: {action_type}"
                )
                continue
            
            # Test 3: Risk level validation
            risk_level = entry.get('risk_level')
            if risk_level not in risk_levels:
                self.validation_results['risk_actions']['failed'] += 1
                self.validation_results['risk_actions']['issues'].append(
                    f"Line {line_num}: Invalid risk_level: {risk_level}"
                )
                continue
            
            # Test 4: Risk score validation
            risk_score = entry.get('risk_score')
            if not isinstance(risk_score, (int, float)) or not (0.0 <= risk_score <= 1.0):
                self.validation_results['risk_actions']['failed'] += 1
                self.validation_results['risk_actions']['issues'].append(
                    f"Line {line_num}: Invalid risk_score: {risk_score} (must be 0.0-1.0)"
                )
                continue
            
            # Test 5: IP address format validation
            source_ip = entry.get('source_ip')
            if not self._is_valid_ip(source_ip):
                self.validation_results['risk_actions']['failed'] += 1
                self.validation_results['risk_actions']['issues'].append(
                    f"Line {line_num}: Invalid source_ip format: {source_ip}"
                )
                continue
            
            # Test 6: Risk score and action consistency
            if not self._validate_risk_action_consistency(risk_score, action_type, risk_level):
                self.validation_results['risk_actions']['failed'] += 1
                self.validation_results['risk_actions']['issues'].append(
                    f"Line {line_num}: Inconsistent risk_score ({risk_score}) and action ({action_type}/{risk_level})"
                )
                continue
            
            # Test 7: Timestamp validation
            try:
                datetime.fromisoformat(entry.get('timestamp', '').replace('Z', '+00:00'))
            except ValueError:
                self.validation_results['risk_actions']['failed'] += 1
                self.validation_results['risk_actions']['issues'].append(
                    f"Line {line_num}: Invalid timestamp format: {entry.get('timestamp')}"
                )
                continue
            
            # If all tests pass
            self.validation_results['risk_actions']['passed'] += 1
        
        total = self.validation_results['risk_actions']['passed'] + self.validation_results['risk_actions']['failed']
        accuracy = (self.validation_results['risk_actions']['passed'] / total * 100) if total > 0 else 0
        
        print(f"Risk Actions Validation: {accuracy:.1f}% ({self.validation_results['risk_actions']['passed']}/{total})")

    def validate_anomaly_detection_log(self, anomalies):
        """Validate anomaly detection log entries"""
        
        print("\n🔍 Validating Anomaly Detection Log")
        print("-" * 38)
        
        required_fields = ['timestamp', 'confidence', 'flow_info', 'statistics']
        
        for entry in anomalies:
            line_num = entry.get('_line_number', 'unknown')
            
            # Test 1: Required fields validation
            missing_fields = [field for field in required_fields if field not in entry]
            if missing_fields:
                self.validation_results['anomaly_detection']['failed'] += 1
                self.validation_results['anomaly_detection']['issues'].append(
                    f"Line {line_num}: Missing required fields: {missing_fields}"
                )
                continue
            
            # Test 2: Confidence score validation
            confidence = entry.get('confidence')
            if not isinstance(confidence, (int, float)) or not (0.0 <= confidence <= 1.0):
                self.validation_results['anomaly_detection']['failed'] += 1
                self.validation_results['anomaly_detection']['issues'].append(
                    f"Line {line_num}: Invalid confidence: {confidence} (must be 0.0-1.0)"
                )
                continue
            
            # Test 3: Flow info structure validation
            flow_info = entry.get('flow_info', {})
            expected_flow_fields = ['protocol', 'src_ip', 'dst_ip', 'src_port', 'dst_port']
            if not isinstance(flow_info, dict) or not all(field in flow_info for field in expected_flow_fields):
                self.validation_results['anomaly_detection']['failed'] += 1
                self.validation_results['anomaly_detection']['issues'].append(
                    f"Line {line_num}: Invalid flow_info structure"
                )
                continue
            
            # Test 4: Statistics structure validation
            statistics = entry.get('statistics', {})
            expected_stats_fields = ['duration', 'packets', 'bytes']
            if not isinstance(statistics, dict) or not all(field in statistics for field in expected_stats_fields):
                self.validation_results['anomaly_detection']['failed'] += 1
                self.validation_results['anomaly_detection']['issues'].append(
                    f"Line {line_num}: Invalid statistics structure"
                )
                continue
            
            # Test 5: Timestamp validation
            try:
                datetime.fromisoformat(entry.get('timestamp', '').replace('Z', '+00:00'))
            except ValueError:
                self.validation_results['anomaly_detection']['failed'] += 1
                self.validation_results['anomaly_detection']['issues'].append(
                    f"Line {line_num}: Invalid timestamp format: {entry.get('timestamp')}"
                )
                continue
            
            # If all tests pass
            self.validation_results['anomaly_detection']['passed'] += 1
        
        total = self.validation_results['anomaly_detection']['passed'] + self.validation_results['anomaly_detection']['failed']
        accuracy = (self.validation_results['anomaly_detection']['passed'] / total * 100) if total > 0 else 0
        
        print(f"Anomaly Detection Validation: {accuracy:.1f}% ({self.validation_results['anomaly_detection']['passed']}/{total})")

    def cross_validate_logs(self, risk_actions, anomalies):
        """Cross-validate consistency between different log files"""
        
        print("\n🔍 Cross-Validating Log Consistency")
        print("-" * 35)
        
        # Group entries by time windows for correlation
        risk_actions_by_time = self._group_by_time_window(risk_actions, 'timestamp')
        anomalies_by_time = self._group_by_time_window(anomalies, 'timestamp')
        
        # Test 1: Temporal correlation validation
        correlated_events = 0
        total_windows = len(risk_actions_by_time)
        
        for time_window, risk_entries in risk_actions_by_time.items():
            if time_window in anomalies_by_time:
                anomaly_entries = anomalies_by_time[time_window]
                
                # Check if high-confidence anomalies led to appropriate risk actions
                high_conf_anomalies = [a for a in anomaly_entries if a.get('confidence', 0) > 0.15]
                blocking_actions = [r for r in risk_entries if r.get('action_type') in ['RATE_LIMIT', 'SHORT_TIMEOUT_BLOCK', 'BLOCK']]
                
                if high_conf_anomalies and blocking_actions:
                    correlated_events += 1
                    self.validation_results['cross_validation']['passed'] += 1
                elif high_conf_anomalies and not blocking_actions:
                    self.validation_results['cross_validation']['failed'] += 1
                    self.validation_results['cross_validation']['issues'].append(
                        f"Time window {time_window}: High confidence anomalies detected but no mitigation actions taken"
                    )
                else:
                    self.validation_results['cross_validation']['passed'] += 1
        
        # Test 2: Source IP consistency validation
        risk_source_ips = set(entry.get('source_ip') for entry in risk_actions if entry.get('source_ip'))
        anomaly_source_ips = set(
            entry.get('flow_info', {}).get('src_ip') 
            for entry in anomalies 
            if entry.get('flow_info', {}).get('src_ip') not in ['unknown', None]
        )
        
        # Check for anomalies without corresponding risk actions
        unhandled_sources = anomaly_source_ips - risk_source_ips
        if unhandled_sources and len(unhandled_sources) > len(anomaly_source_ips) * 0.1:  # More than 10% unhandled
            self.validation_results['cross_validation']['failed'] += 1
            self.validation_results['cross_validation']['issues'].append(
                f"Significant number of anomaly sources without risk actions: {len(unhandled_sources)} sources"
            )
        else:
            self.validation_results['cross_validation']['passed'] += 1
        
        cross_total = self.validation_results['cross_validation']['passed'] + self.validation_results['cross_validation']['failed']
        cross_accuracy = (self.validation_results['cross_validation']['passed'] / cross_total * 100) if cross_total > 0 else 0
        
        print(f"Cross-Validation Accuracy: {cross_accuracy:.1f}% ({self.validation_results['cross_validation']['passed']}/{cross_total})")

    def analyze_patterns(self, risk_actions, anomalies):
        """Analyze patterns in the log data for insights"""
        
        print("\n📊 Pattern Analysis")
        print("-" * 20)
        
        # Analyze action distribution
        action_distribution = Counter(entry.get('action_type') for entry in risk_actions)
        print("Action Distribution:")
        for action, count in action_distribution.most_common():
            percentage = (count / len(risk_actions) * 100) if risk_actions else 0
            print(f"   {action}: {count} ({percentage:.1f}%)")
        
        # Analyze risk level distribution
        risk_distribution = Counter(entry.get('risk_level') for entry in risk_actions)
        print("\nRisk Level Distribution:")
        for risk_level, count in risk_distribution.most_common():
            percentage = (count / len(risk_actions) * 100) if risk_actions else 0
            print(f"   {risk_level}: {count} ({percentage:.1f}%)")
        
        # Analyze top source IPs
        source_ip_counts = Counter(entry.get('source_ip') for entry in risk_actions)
        print(f"\nTop 5 Source IPs by Actions:")
        for ip, count in source_ip_counts.most_common(5):
            print(f"   {ip}: {count} actions")
        
        # Analyze confidence score distribution for anomalies
        if anomalies:
            confidence_scores = [entry.get('confidence', 0) for entry in anomalies]
            avg_confidence = sum(confidence_scores) / len(confidence_scores)
            max_confidence = max(confidence_scores)
            min_confidence = min(confidence_scores)
            
            print(f"\nAnomaly Confidence Scores:")
            print(f"   Average: {avg_confidence:.3f}")
            print(f"   Maximum: {max_confidence:.3f}")
            print(f"   Minimum: {min_confidence:.3f}")
        
        return {
            'action_distribution': dict(action_distribution),
            'risk_distribution': dict(risk_distribution),
            'top_source_ips': dict(source_ip_counts.most_common(10)),
            'confidence_stats': {
                'average': sum([entry.get('confidence', 0) for entry in anomalies]) / len(anomalies) if anomalies else 0,
                'max': max([entry.get('confidence', 0) for entry in anomalies]) if anomalies else 0,
                'min': min([entry.get('confidence', 0) for entry in anomalies]) if anomalies else 0
            }
        }

    def _validate_risk_action_consistency(self, risk_score, action_type, risk_level):
        """Validate consistency between risk score and action taken"""
        
        # Define expected mappings based on system thresholds
        if risk_score < 0.08:
            return risk_level == 'LOW' and action_type == 'ALLOW'
        elif risk_score < 0.18:
            return risk_level in ['LOW', 'MEDIUM'] and action_type in ['ALLOW', 'RATE_LIMIT']
        elif risk_score < 0.25:
            return risk_level in ['MEDIUM', 'HIGH'] and action_type in ['RATE_LIMIT', 'SHORT_TIMEOUT_BLOCK']
        else:
            return risk_level in ['HIGH', 'CRITICAL'] and action_type in ['SHORT_TIMEOUT_BLOCK', 'BLOCK']

    def _is_valid_ip(self, ip_str):
        """Validate IP address format"""
        if not ip_str or ip_str == 'unknown':
            return True  # Allow unknown IPs for some log entries
        
        try:
            parts = ip_str.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False

    def _group_by_time_window(self, entries, timestamp_field, window_seconds=60):
        """Group log entries by time windows for correlation analysis"""
        
        grouped = defaultdict(list)
        
        for entry in entries:
            try:
                timestamp_str = entry.get(timestamp_field, '')
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                
                # Round timestamp to nearest window
                window_start = timestamp.replace(second=timestamp.second // window_seconds * window_seconds, microsecond=0)
                
                grouped[window_start].append(entry)
            except (ValueError, AttributeError):
                continue  # Skip entries with invalid timestamps
        
        return dict(grouped)

    def run_comprehensive_validation(self):
        """Run complete validation suite"""
        
        print("🚀 Starting JSON Log Validation")
        print("=" * 40)
        
        # Load log data
        logs = self.load_json_logs()
        
        # Run validation tests
        self.validate_risk_actions_log(logs['risk_actions'])
        self.validate_anomaly_detection_log(logs['anomalies'])
        self.cross_validate_logs(logs['risk_actions'], logs['anomalies'])
        
        # Analyze patterns
        pattern_analysis = self.analyze_patterns(logs['risk_actions'], logs['anomalies'])
        
        # Generate comprehensive report
        self._generate_validation_report(pattern_analysis)
        
        return {
            'validation_results': self.validation_results,
            'pattern_analysis': pattern_analysis,
            'log_counts': {
                'risk_actions': len(logs['risk_actions']),
                'anomalies': len(logs['anomalies'])
            }
        }

    def _generate_validation_report(self, pattern_analysis):
        """Generate comprehensive validation report"""
        
        # Calculate overall statistics
        total_passed = sum(result['passed'] for result in self.validation_results.values())
        total_failed = sum(result['failed'] for result in self.validation_results.values())
        total_tests = total_passed + total_failed
        overall_accuracy = (total_passed / total_tests * 100) if total_tests > 0 else 0
        
        print("\n" + "=" * 50)
        print("📊 JSON LOG VALIDATION SUMMARY")
        print("=" * 50)
        print(f"Overall Validation Accuracy: {overall_accuracy:.1f}%")
        print(f"Total Validations: {total_tests}")
        print(f"Passed: {total_passed}")
        print(f"Failed: {total_failed}")
        
        if overall_accuracy >= 95:
            print("🏆 EXCELLENT: Log integrity and consistency are excellent")
        elif overall_accuracy >= 85:
            print("✅ GOOD: Log quality is acceptable with minor issues")
        elif overall_accuracy >= 70:
            print("⚠️ FAIR: Log quality needs improvement")
        else:
            print("❌ POOR: Significant log quality issues detected")
        
        # Report issues by category
        for category, results in self.validation_results.items():
            if results['issues']:
                print(f"\n⚠️ Issues in {category.replace('_', ' ').title()}:")
                for issue in results['issues'][:5]:  # Show first 5 issues
                    print(f"   • {issue}")
                if len(results['issues']) > 5:
                    print(f"   ... and {len(results['issues']) - 5} more issues")
        
        # Save detailed report
        report = {
            'summary': {
                'overall_accuracy': overall_accuracy,
                'total_validations': total_tests,
                'passed': total_passed,
                'failed': total_failed,
                'validation_timestamp': datetime.now().isoformat()
            },
            'validation_results': self.validation_results,
            'pattern_analysis': pattern_analysis
        }
        
        with open('json_log_validation_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📋 Detailed report saved to: json_log_validation_report.json")

def main():
    """Main execution function"""
    
    print("🔬 JSON Log Validation Test Suite")
    print("Testing Log Integrity and Decision Consistency")
    print("-" * 50)
    
    validator = JSONLogValidator()
    validator.run_comprehensive_validation()

if __name__ == "__main__":
    main()
