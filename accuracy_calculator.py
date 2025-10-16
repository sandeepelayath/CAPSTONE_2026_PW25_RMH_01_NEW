#!/usr/bin/env python3
"""
System Accuracy Calculator for Risk-Based Mitigation System
Analyzes test logs to calculate detection accuracy, false positives, and performance metrics.
"""

import json
import os
import sys
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import statistics

class SystemAccuracyCalculator:
    def __init__(self):
        # Risk thresholds consistent with controller (mitigation_manager.py)
        # LOW < 0.08, MEDIUM < 0.12, HIGH < 0.15, CRITICAL >= 0.15
        self.risk_thresholds = {
            'LOW': 0.08,      # < 0.08 (ALLOW)
            'MEDIUM': 0.12,   # 0.08 - 0.12 (RATE_LIMIT)
            'HIGH': 0.15,     # 0.12 - 0.15 (REDIRECT_TO_HONEYPOT)
            'CRITICAL': 0.15  # > 0.15 (SHORT_TIMEOUT_BLOCK)
        }
        
        # Expected behaviors for test IPs (ground truth) - Based on test_topology.py
        self.ground_truth = {
            # Core topology hosts (from test_topology.py)
            '10.0.0.1': 'LEGITIMATE',     # h1 - normal user
            '10.0.0.2': 'LEGITIMATE',     # h2 - web server
            '10.0.0.3': 'LOW_RISK',       # h3 - low risk tester
            '10.0.0.4': 'MEDIUM_RISK',    # h4 - medium risk tester
            '10.0.0.5': 'HIGH_RISK',      # h5 - high risk tester
            '10.0.0.6': 'MALICIOUS',      # h6 - multi-stage attacker
            '10.0.0.7': 'LEGITIMATE',     # h7 - whitelist candidate
            '10.0.0.8': 'MALICIOUS',      # h8 - blacklist candidate
            
            # Special test IPs (honeypot and synthetic test data)
            '10.0.0.9': 'HONEYPOT',       # Honeypot IP (critical risk trigger)
            '10.0.0.50': 'MALICIOUS',     # Honeypot accessor
            '10.0.0.100': 'LEGITIMATE',   # Normal traffic
            '10.0.0.150': 'LEGITIMATE',   # Low risk legitimate
            '10.0.0.175': 'MEDIUM_RISK',  # Medium risk
            '10.0.0.200': 'HIGH_RISK',    # High risk
            '10.0.0.250': 'MALICIOUS',    # Critical risk malicious
            
            # Additional synthetic test ranges
            '10.0.0.10': 'LEGITIMATE',    # Additional legitimate host
            '10.0.0.11': 'LEGITIMATE',    # Additional legitimate host
            '10.0.0.12': 'LOW_RISK',      # Additional low risk host
            '10.0.0.13': 'LOW_RISK',      # Additional low risk host
            '10.0.0.14': 'MEDIUM_RISK',   # Additional medium risk host
            '10.0.0.15': 'MEDIUM_RISK',   # Additional medium risk host
            '10.0.0.16': 'HIGH_RISK',     # Additional high risk host
            '10.0.0.17': 'HIGH_RISK',     # Additional high risk host
            '10.0.0.18': 'MALICIOUS',     # Additional malicious host
            '10.0.0.19': 'MALICIOUS',     # Additional malicious host
        }
        
        # Expected mitigation actions for each category
        self.expected_actions = {
            'LEGITIMATE': ['ALLOW'],
            'LOW_RISK': ['ALLOW', 'RATE_LIMIT'],  # May get rate limited if risk increases slightly
            'MEDIUM_RISK': ['RATE_LIMIT', 'ALLOW'],
            'HIGH_RISK': ['REDIRECT_TO_HONEYPOT', 'RATE_LIMIT', 'SHORT_TIMEOUT_BLOCK'],
            'MALICIOUS': ['SHORT_TIMEOUT_BLOCK', 'REDIRECT_TO_HONEYPOT', 'RATE_LIMIT'],
            'HONEYPOT': ['SHORT_TIMEOUT_BLOCK']  # Honeypot access should always be blocked immediately
        }

    def load_test_metrics(self):
        """Load all test metric files"""
        metrics_dir = '/home/sandeep/Capstone_Phase3/mininet/test_logs'
        metrics_files = []
        
        if not os.path.exists(metrics_dir):
            print(f"❌ Test metrics directory not found: {metrics_dir}")
            return []
        
        for filename in os.listdir(metrics_dir):
            if filename.startswith('test_metrics_') and filename.endswith('.json'):
                file_path = os.path.join(metrics_dir, filename)
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        data['filename'] = filename
                        metrics_files.append(data)
                except Exception as e:
                    print(f"⚠️ Error loading {filename}: {e}")
        
        return sorted(metrics_files, key=lambda x: x['filename'])

    def load_mitigation_logs(self):
        """Load risk mitigation action logs"""
        log_files = [
            '/home/sandeep/Capstone_Phase3/controller/risk_mitigation_actions.json',
            '/home/sandeep/Capstone_Phase3/controller/validation_tests/risk_mitigation_actions.json'
        ]
        
        actions = []
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r') as f:
                        for line in f:
                            if line.strip():
                                try:
                                    action = json.loads(line)
                                    actions.append(action)
                                except json.JSONDecodeError:
                                    continue
                    print(f"✅ Loaded {len(actions)} actions from {log_file}")
                    break
                except Exception as e:
                    print(f"⚠️ Error loading {log_file}: {e}")
        
        return actions

    def _get_selection_method(self, expected_category):
        """Get description of selection method used for each category"""
        methods = {
            'MALICIOUS': 'Peak Risk (Attack Detection)',
            'HIGH_RISK': 'Peak Risk (Attack Detection)', 
            'LEGITIMATE': 'Median Risk (Typical Behavior)',
            'LOW_RISK': 'Median Risk (Typical Behavior)',
            'MEDIUM_RISK': '75th Percentile (Elevated Behavior)',
            'HONEYPOT': 'First High-Risk Detection'
        }
        return methods.get(expected_category, 'Latest Action')

    def _select_representative_action(self, ip_action_list, expected_category):
        """
        Select the most representative action for accuracy assessment based on expected behavior.
        
        Logic:
        - MALICIOUS/HIGH_RISK: Use peak risk score (during active attack)
        - LEGITIMATE/LOW_RISK: Use median or latest to avoid temporary spikes
        - MEDIUM_RISK: Use 75th percentile to capture elevated but not peak behavior
        - HONEYPOT: Use first high-confidence detection
        
        Args:
            ip_action_list: List of actions for this IP
            expected_category: Expected behavior category
            
        Returns:
            dict: Most representative action record
        """
        if not ip_action_list:
            return {}
        
        # Sort by timestamp for temporal analysis
        sorted_actions = sorted(ip_action_list, key=lambda x: x.get('timestamp', ''))
        
        if expected_category in ['MALICIOUS', 'HIGH_RISK']:
            # For malicious hosts: Find peak risk score during attack period
            # This represents the system's ability to detect threats at their worst
            peak_action = max(ip_action_list, key=lambda x: x.get('risk_score', 0))
            
            # Ensure we're not picking an anomalous outlier by checking if peak is reasonable
            risk_scores = [action.get('risk_score', 0) for action in ip_action_list]
            avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
            
            # If peak is more than 3x average, use 90th percentile instead
            if peak_action.get('risk_score', 0) > avg_risk * 3:
                risk_scores.sort()
                percentile_90_idx = int(len(risk_scores) * 0.9)
                target_score = risk_scores[min(percentile_90_idx, len(risk_scores) - 1)]
                
                # Find action closest to 90th percentile
                return min(ip_action_list, 
                          key=lambda x: abs(x.get('risk_score', 0) - target_score))
            
            return peak_action
            
        elif expected_category in ['LEGITIMATE', 'LOW_RISK']:
            # For legitimate hosts: Use median to avoid temporary spikes
            # This gives us the "typical" behavior, not anomalous moments
            risk_scores = [(action.get('risk_score', 0), action) for action in ip_action_list]
            risk_scores.sort(key=lambda x: x[0])
            
            median_idx = len(risk_scores) // 2
            return risk_scores[median_idx][1]
            
        elif expected_category == 'MEDIUM_RISK':
            # For medium risk: Use 75th percentile - elevated but not peak
            risk_scores = [(action.get('risk_score', 0), action) for action in ip_action_list]
            risk_scores.sort(key=lambda x: x[0])
            
            percentile_75_idx = int(len(risk_scores) * 0.75)
            return risk_scores[min(percentile_75_idx, len(risk_scores) - 1)][1]
            
        elif expected_category == 'HONEYPOT':
            # For honeypot: Use first high-confidence detection (immediate response)
            high_risk_actions = [action for action in sorted_actions 
                               if action.get('risk_score', 0) > self.risk_thresholds['HIGH']]
            
            if high_risk_actions:
                return high_risk_actions[0]  # First high-risk detection
            else:
                return sorted_actions[-1]  # Latest if no high-risk found
                
        else:
            # Default: Use latest action
            return sorted_actions[-1]

    def analyze_risk_classification_accuracy(self, actions):
        """Analyze risk classification accuracy"""
        print("\n" + "="*80)
        print("🎯 RISK CLASSIFICATION ACCURACY ANALYSIS")
        print("="*80)
        
        # Group actions by source IP
        ip_actions = defaultdict(list)
        for action in actions:
            ip = action.get('source_ip')
            if ip:
                ip_actions[ip].append(action)
        
        correct_classifications = 0
        total_classifications = 0
        classification_details = []
        
        for ip, ip_action_list in ip_actions.items():
            expected_category = self.ground_truth.get(ip, 'UNKNOWN')
            if expected_category == 'UNKNOWN':
                continue
            
            # Smart risk assessment selection based on expected behavior
            selected_action = self._select_representative_action(ip_action_list, expected_category)
            actual_risk_score = selected_action.get('risk_score', 0)
            actual_risk_level = selected_action.get('risk_level', 'UNKNOWN')
            actual_action = selected_action.get('action_type', 'UNKNOWN')
            
            # Check if classification is correct
            expected_actions = self.expected_actions.get(expected_category, [])
            is_correct = actual_action in expected_actions
            
            if is_correct:
                correct_classifications += 1
            
            total_classifications += 1
            
            # Determine selection method used for transparency
            selection_method = self._get_selection_method(expected_category)
            
            classification_details.append({
                'ip': ip,
                'expected_category': expected_category,
                'expected_actions': expected_actions,
                'actual_action': actual_action,
                'actual_risk_score': actual_risk_score,
                'actual_risk_level': actual_risk_level,
                'is_correct': is_correct,
                'action_count': len(ip_action_list),
                'selection_method': selection_method
            })
        
        # Calculate overall accuracy
        if total_classifications > 0:
            overall_accuracy = (correct_classifications / total_classifications) * 100
        else:
            overall_accuracy = 0
        
        print(f"📊 OVERALL CLASSIFICATION ACCURACY: {overall_accuracy:.2f}%")
        print(f"📈 Correct Classifications: {correct_classifications}/{total_classifications}")
        
        # Detailed breakdown
        print(f"\n📋 DETAILED CLASSIFICATION RESULTS:")
        print(f"  Format: IP | Expected -> Actual | Risk Score | Selection Method | Actions Count")
        print(f"  " + "-" * 80)
        for detail in sorted(classification_details, key=lambda x: x['ip']):
            status = "✅" if detail['is_correct'] else "❌"
            print(f"  {status} {detail['ip']}: {detail['expected_category']} -> {detail['actual_action']} "
                  f"| Risk: {detail['actual_risk_score']:.3f} | {detail['selection_method']} | "
                  f"Actions: {detail['action_count']}")
        
        return overall_accuracy, classification_details

    def analyze_false_positives_negatives(self, classification_details):
        """Analyze false positives and false negatives"""
        print(f"\n🔍 FALSE POSITIVE/NEGATIVE ANALYSIS:")
        
        false_positives = 0  # Legitimate traffic incorrectly blocked/limited
        false_negatives = 0  # Malicious traffic incorrectly allowed
        true_positives = 0   # Malicious traffic correctly blocked/limited
        true_negatives = 0   # Legitimate traffic correctly allowed
        
        for detail in classification_details:
            expected = detail['expected_category']
            actual_action = detail['actual_action']
            
            # Classify as malicious or legitimate based on expected category
            is_expected_malicious = expected in ['MALICIOUS', 'HIGH_RISK']
            is_action_blocking = actual_action in ['SHORT_TIMEOUT_BLOCK', 'REDIRECT_TO_HONEYPOT']
            
            if is_expected_malicious and is_action_blocking:
                true_positives += 1
            elif is_expected_malicious and not is_action_blocking:
                false_negatives += 1
            elif not is_expected_malicious and is_action_blocking:
                false_positives += 1
            else:
                true_negatives += 1
        
        total = len(classification_details)
        if total > 0:
            fp_rate = (false_positives / total) * 100
            fn_rate = (false_negatives / total) * 100
            precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
            recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        else:
            fp_rate = fn_rate = precision = recall = f1_score = 0
        
        print(f"  🎯 True Positives (Correct blocks): {true_positives}")
        print(f"  ✅ True Negatives (Correct allows): {true_negatives}")
        print(f"  ❌ False Positives (Incorrect blocks): {false_positives} ({fp_rate:.2f}%)")
        print(f"  ⚠️ False Negatives (Missed threats): {false_negatives} ({fn_rate:.2f}%)")
        print(f"  📊 Precision: {precision:.3f}")
        print(f"  📊 Recall: {recall:.3f}")
        print(f"  📊 F1-Score: {f1_score:.3f}")
        
        return {
            'true_positives': true_positives,
            'true_negatives': true_negatives,
            'false_positives': false_positives,
            'false_negatives': false_negatives,
            'fp_rate': fp_rate,
            'fn_rate': fn_rate,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score
        }

    def analyze_response_times(self, actions):
        """Analyze system response times"""
        print(f"\n⏱️ RESPONSE TIME ANALYSIS:")
        
        # Group by IP and analyze time between first detection and action
        ip_timelines = defaultdict(list)
        for action in actions:
            ip = action.get('source_ip')
            timestamp = action.get('timestamp')
            if ip and timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    ip_timelines[ip].append((dt, action))
                except:
                    continue
        
        response_times = []
        escalation_times = []
        
        for ip, timeline in ip_timelines.items():
            # Sort by timestamp
            timeline.sort(key=lambda x: x[0])
            
            if len(timeline) > 1:
                first_time = timeline[0][0]
                
                # Find first blocking action
                first_block_time = None
                for dt, action in timeline:
                    if action.get('action_type') in ['SHORT_TIMEOUT_BLOCK', 'REDIRECT_TO_HONEYPOT']:
                        first_block_time = dt
                        break
                
                if first_block_time:
                    response_time = (first_block_time - first_time).total_seconds()
                    response_times.append(response_time)
                
                # Analyze escalation pattern
                actions_sequence = [action['action_type'] for _, action in timeline]
                if len(set(actions_sequence)) > 1:  # Multiple different actions
                    escalation_time = (timeline[-1][0] - timeline[0][0]).total_seconds()
                    escalation_times.append(escalation_time)
        
        if response_times:
            avg_response = statistics.mean(response_times)
            min_response = min(response_times)
            max_response = max(response_times)
            print(f"  📊 Average Response Time: {avg_response:.2f} seconds")
            print(f"  🏃 Fastest Response: {min_response:.2f} seconds")
            print(f"  🐌 Slowest Response: {max_response:.2f} seconds")
        else:
            print(f"  ⚠️ No response time data available")
        
        if escalation_times:
            avg_escalation = statistics.mean(escalation_times)
            print(f"  📈 Average Escalation Time: {avg_escalation:.2f} seconds")
        
        return {
            'avg_response_time': statistics.mean(response_times) if response_times else 0,
            'response_times': response_times,
            'escalation_times': escalation_times
        }

    def analyze_system_performance(self, metrics_files):
        """Analyze system performance metrics"""
        print(f"\n🖥️ SYSTEM PERFORMANCE ANALYSIS:")
        
        if not metrics_files:
            print(f"  ⚠️ No performance metrics available")
            return {}
        
        all_cpu_usage = []
        all_memory_usage = []
        all_packet_rates = []
        network_errors = 0
        total_samples = 0
        
        for metrics in metrics_files:
            system_metrics = metrics.get('system_metrics', [])
            
            for sample in system_metrics:
                total_samples += 1
                
                cpu = sample.get('cpu_percent', 0)
                memory = sample.get('memory_percent', 0)
                
                all_cpu_usage.append(cpu)
                all_memory_usage.append(memory)
                
                # Calculate packet rate if we have network I/O data
                network_io = sample.get('network_io', {})
                if network_io:
                    packets_sent = network_io.get('packets_sent', 0)
                    packets_recv = network_io.get('packets_recv', 0)
                    total_packets = packets_sent + packets_recv
                    all_packet_rates.append(total_packets)
                    
                    # Count network errors
                    errin = network_io.get('errin', 0)
                    errout = network_io.get('errout', 0)
                    dropin = network_io.get('dropin', 0)
                    dropout = network_io.get('dropout', 0)
                    network_errors += errin + errout + dropin + dropout
        
        performance_stats = {}
        
        if all_cpu_usage:
            performance_stats['avg_cpu'] = statistics.mean(all_cpu_usage)
            performance_stats['max_cpu'] = max(all_cpu_usage)
            performance_stats['min_cpu'] = min(all_cpu_usage)
            print(f"  🖥️ CPU Usage - Avg: {performance_stats['avg_cpu']:.2f}%, "
                  f"Max: {performance_stats['max_cpu']:.2f}%, Min: {performance_stats['min_cpu']:.2f}%")
        
        if all_memory_usage:
            performance_stats['avg_memory'] = statistics.mean(all_memory_usage)
            performance_stats['max_memory'] = max(all_memory_usage)
            performance_stats['min_memory'] = min(all_memory_usage)
            print(f"  🧠 Memory Usage - Avg: {performance_stats['avg_memory']:.2f}%, "
                  f"Max: {performance_stats['max_memory']:.2f}%, Min: {performance_stats['min_memory']:.2f}%")
        
        if all_packet_rates:
            performance_stats['avg_packets'] = statistics.mean(all_packet_rates)
            performance_stats['max_packets'] = max(all_packet_rates)
            print(f"  📦 Packet Processing - Avg: {performance_stats['avg_packets']:,.0f}, "
                  f"Peak: {performance_stats['max_packets']:,.0f}")
        
        if total_samples > 0:
            error_rate = (network_errors / total_samples) * 100
            performance_stats['error_rate'] = error_rate
            print(f"  ⚠️ Network Error Rate: {error_rate:.4f}%")
        
        return performance_stats

    def analyze_mitigation_effectiveness(self, actions):
        """Analyze effectiveness of different mitigation strategies"""
        print(f"\n🛡️ MITIGATION EFFECTIVENESS ANALYSIS:")
        
        # Count mitigation types
        action_counts = Counter()
        risk_distributions = defaultdict(list)
        
        for action in actions:
            action_type = action.get('action_type', 'UNKNOWN')
            risk_score = action.get('risk_score', 0)
            
            action_counts[action_type] += 1
            risk_distributions[action_type].append(risk_score)
        
        total_actions = sum(action_counts.values())
        
        print(f"  📊 Total Mitigation Actions: {total_actions}")
        
        for action_type, count in action_counts.most_common():
            percentage = (count / total_actions) * 100 if total_actions > 0 else 0
            
            # Calculate average risk score for this action type
            risks = risk_distributions[action_type]
            avg_risk = statistics.mean(risks) if risks else 0
            
            print(f"    • {action_type}: {count} ({percentage:.1f}%) - Avg Risk: {avg_risk:.3f}")
        
        # Analyze risk score distributions
        all_risks = []
        for risks in risk_distributions.values():
            all_risks.extend(risks)
        
        if all_risks:
            print(f"\n  📈 Risk Score Statistics:")
            print(f"    • Average: {statistics.mean(all_risks):.3f}")
            print(f"    • Median: {statistics.median(all_risks):.3f}")
            print(f"    • Min: {min(all_risks):.3f}")
            print(f"    • Max: {max(all_risks):.3f}")
            print(f"    • Standard Deviation: {statistics.stdev(all_risks):.3f}")
        
        return {
            'action_counts': dict(action_counts),
            'risk_distributions': dict(risk_distributions),
            'total_actions': total_actions
        }

    def generate_accuracy_report(self):
        """Generate comprehensive accuracy report"""
        print("🎯 SYSTEM ACCURACY ANALYSIS REPORT")
        print("="*80)
        print(f"Generated: {datetime.now().isoformat()}")
        
        # Load data
        print("\n📥 Loading test data...")
        actions = self.load_mitigation_logs()
        metrics_files = self.load_test_metrics()
        
        if not actions:
            print("❌ No mitigation action logs found! Cannot calculate accuracy.")
            return
        
        print(f"✅ Loaded {len(actions)} mitigation actions")
        print(f"✅ Loaded {len(metrics_files)} performance metric files")
        
        # Perform analyses
        overall_accuracy, classification_details = self.analyze_risk_classification_accuracy(actions)
        fp_fn_analysis = self.analyze_false_positives_negatives(classification_details)
        response_analysis = self.analyze_response_times(actions)
        performance_analysis = self.analyze_system_performance(metrics_files)
        mitigation_analysis = self.analyze_mitigation_effectiveness(actions)
        
        # Summary Report
        print(f"\n" + "="*80)
        print("📊 ACCURACY SUMMARY REPORT")
        print("="*80)
        
        print(f"🎯 Overall Classification Accuracy: {overall_accuracy:.2f}%")
        print(f"🔍 False Positive Rate: {fp_fn_analysis['fp_rate']:.2f}%")
        print(f"⚠️ False Negative Rate: {fp_fn_analysis['fn_rate']:.2f}%")
        print(f"📊 Precision: {fp_fn_analysis['precision']:.3f}")
        print(f"📊 Recall: {fp_fn_analysis['recall']:.3f}")
        print(f"📊 F1-Score: {fp_fn_analysis['f1_score']:.3f}")
        
        if response_analysis['avg_response_time'] > 0:
            print(f"⏱️ Average Response Time: {response_analysis['avg_response_time']:.2f} seconds")
        
        if 'avg_cpu' in performance_analysis:
            print(f"🖥️ Average CPU Usage: {performance_analysis['avg_cpu']:.2f}%")
        
        if 'avg_memory' in performance_analysis:
            print(f"🧠 Average Memory Usage: {performance_analysis['avg_memory']:.2f}%")
        
        # Grade the system
        print(f"\n📈 SYSTEM GRADE:")
        if overall_accuracy >= 95:
            grade = "A+ (Excellent)"
        elif overall_accuracy >= 90:
            grade = "A (Very Good)"
        elif overall_accuracy >= 85:
            grade = "B+ (Good)"
        elif overall_accuracy >= 80:
            grade = "B (Acceptable)"
        elif overall_accuracy >= 75:
            grade = "C+ (Below Average)"
        elif overall_accuracy >= 70:
            grade = "C (Poor)"
        else:
            grade = "D (Needs Improvement)"
        
        print(f"🏆 {grade}")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        if fp_fn_analysis['fp_rate'] > 5:
            print("  • Consider adjusting risk thresholds to reduce false positives")
        
        if fp_fn_analysis['fn_rate'] > 3:
            print("  • Enhance ML model training to reduce false negatives")
        
        if response_analysis['avg_response_time'] > 10:
            print("  • Optimize detection pipeline for faster response times")
        
        if performance_analysis.get('avg_cpu', 0) > 70:
            print("  • Consider CPU optimization for sustained performance")
        
        if performance_analysis.get('avg_memory', 0) > 80:
            print("  • Monitor memory usage for potential leaks")
        
        print(f"\n✅ Analysis Complete!")
        
        return {
            'overall_accuracy': overall_accuracy,
            'fp_fn_analysis': fp_fn_analysis,
            'response_analysis': response_analysis,
            'performance_analysis': performance_analysis,
            'mitigation_analysis': mitigation_analysis,
            'grade': grade
        }


def main():
    """Main function"""
    calculator = SystemAccuracyCalculator()
    results = calculator.generate_accuracy_report()
    
    # Save results to file
    output_file = '/home/sandeep/Capstone_Phase3/system_accuracy_report.json'
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n📄 Detailed results saved to: {output_file}")
    except Exception as e:
        print(f"⚠️ Could not save results: {e}")


if __name__ == '__main__':
    main()
