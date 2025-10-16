#!/usr/bin/env python3
"""
Comprehensive Mitigation System Test Runner

This script executes all validation tests for the Risk-Based Mitigation Manager
to provide a complete accuracy assessment of the network security system.

Test Suites:
1. Mitigation Accuracy Tests - Validates security decisions against expected outcomes
2. JSON Log Validation - Ensures log data integrity and decision consistency
3. Combined Analysis - Cross-validates system behavior and logging accuracy

Usage:
    cd validation_tests
    python run_validation_tests.py

Output:
- Console reports with pass/fail statistics
- Detailed JSON reports for further analysis
- Recommendations for system improvements

Author: Network Security Team
Version: 1.0
Date: 2025
"""

import sys
import os
import time
from datetime import datetime

# Import test modules
try:
    from test_mitigation_accuracy import MitigationAccuracyValidator
    from validate_json_logs import JSONLogValidator
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Ensure test modules are in the same directory")
    sys.exit(1)

class ComprehensiveTestRunner:
    """
    Orchestrates comprehensive validation testing for the mitigation system.
    
    This class coordinates multiple test suites to provide a holistic view
    of system accuracy, reliability, and compliance with security policies.
    """
    
    def __init__(self):
        """Initialize the comprehensive test runner"""
        self.start_time = datetime.now()
        self.test_results = {}
    
    def run_mitigation_accuracy_tests(self):
        """Execute mitigation accuracy validation tests"""
        print("🎯 PHASE 1: MITIGATION ACCURACY VALIDATION")
        print("=" * 60)
        
        try:
            validator = MitigationAccuracyValidator()
            validator.run_validation_tests()
            
            # Collect results
            total_tests = validator.passed_tests + validator.failed_tests
            accuracy = (validator.passed_tests / total_tests * 100) if total_tests > 0 else 0
            
            self.test_results['mitigation_accuracy'] = {
                'total_tests': total_tests,
                'passed': validator.passed_tests,
                'failed': validator.failed_tests,
                'accuracy': accuracy,
                'status': 'COMPLETED'
            }
            
            print(f"✅ Phase 1 Complete - Accuracy: {accuracy:.1f}%")
            
        except Exception as e:
            print(f"❌ Phase 1 Failed: {str(e)}")
            self.test_results['mitigation_accuracy'] = {
                'status': 'FAILED',
                'error': str(e)
            }
    
    def run_json_log_validation(self):
        """Execute JSON log validation tests"""
        print("\n📋 PHASE 2: JSON LOG VALIDATION")
        print("=" * 60)
        
        try:
            validator = JSONLogValidator()
            results = validator.run_comprehensive_validation()
            
            # Calculate overall validation accuracy
            validation_results = results['validation_results']
            
            total_passed = (validation_results['risk_actions']['passed'] + 
                           validation_results['anomaly_detection']['passed'] +
                           validation_results['cross_validation']['passed'])
            
            total_failed = (validation_results['risk_actions']['failed'] +
                           validation_results['anomaly_detection']['failed'] +
                           validation_results['cross_validation']['failed'])
            
            total_validations = total_passed + total_failed
            accuracy = (total_passed / total_validations * 100) if total_validations > 0 else 0
            
            self.test_results['json_log_validation'] = {
                'total_validations': total_validations,
                'passed': total_passed,
                'failed': total_failed,
                'accuracy': accuracy,
                'pattern_analysis': results['pattern_analysis'],
                'status': 'COMPLETED'
            }
            
            print(f"✅ Phase 2 Complete - Validation Accuracy: {accuracy:.1f}%")
            
        except Exception as e:
            print(f"❌ Phase 2 Failed: {str(e)}")
            self.test_results['json_log_validation'] = {
                'status': 'FAILED',
                'error': str(e)
            }
    
    def generate_comprehensive_report(self):
        """Generate comprehensive system validation report"""
        
        end_time = datetime.now()
        execution_time = (end_time - self.start_time).total_seconds()
        
        print("\n" + "=" * 70)
        print("🏆 COMPREHENSIVE MITIGATION SYSTEM VALIDATION REPORT")
        print("=" * 70)
        print(f"Execution Time: {execution_time:.2f} seconds")
        print(f"Test Start: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Test End: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Overall system assessment
        overall_status = "PASSED"
        issues = []
        
        # Analyze mitigation accuracy results
        if 'mitigation_accuracy' in self.test_results:
            ma_results = self.test_results['mitigation_accuracy']
            if ma_results.get('status') == 'COMPLETED':
                accuracy = ma_results['accuracy']
                print(f"\n🎯 Mitigation Accuracy: {accuracy:.1f}%")
                print(f"   Tests Passed: {ma_results['passed']}/{ma_results['total_tests']}")
                
                if accuracy < 75:
                    overall_status = "FAILED"
                    issues.append("Mitigation accuracy below acceptable threshold (75%)")
                elif accuracy < 90:
                    issues.append("Mitigation accuracy could be improved (target: 90%+)")
            else:
                overall_status = "FAILED"
                issues.append("Mitigation accuracy tests failed to execute")
        
        # Analyze JSON log validation results
        if 'json_log_validation' in self.test_results:
            jlv_results = self.test_results['json_log_validation']
            if jlv_results.get('status') == 'COMPLETED':
                accuracy = jlv_results['accuracy']
                print(f"\n📋 Log Validation Accuracy: {accuracy:.1f}%")
                print(f"   Validations Passed: {jlv_results['passed']}/{jlv_results['total_validations']}")
                
                if accuracy < 90:
                    overall_status = "FAILED"
                    issues.append("Log validation accuracy below acceptable threshold (90%)")
            else:
                overall_status = "FAILED" 
                issues.append("JSON log validation failed to execute")
        
        # System recommendations
        print(f"\n🔍 Overall System Status: {overall_status}")
        
        if issues:
            print("\n⚠️ Issues Identified:")
            for issue in issues:
                print(f"   • {issue}")
        
        print("\n📈 Recommendations:")
        if overall_status == "PASSED":
            print("   ✅ System is operating within acceptable parameters")
            print("   ✅ Security decisions are accurate and well-logged")
            print("   ✅ Ready for production deployment")
        else:
            print("   🔧 Review and adjust ML model thresholds")
            print("   🔧 Validate training data quality and model performance") 
            print("   🔧 Check system configuration and policy definitions")
            print("   🔧 Consider retraining models with additional data")
        
        # Save comprehensive report
        comprehensive_report = {
            'test_execution': {
                'start_time': self.start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'execution_time_seconds': execution_time,
                'overall_status': overall_status
            },
            'test_results': self.test_results,
            'issues_identified': issues,
            'generated_files': [
                'mitigation_accuracy_report.json',
                'json_log_validation_report.json',
                'comprehensive_validation_report.json'
            ]
        }
        
        with open('comprehensive_validation_report.json', 'w') as f:
            import json
            json.dump(comprehensive_report, f, indent=2)
        
        print(f"\n📊 Reports Generated:")
        print("   • mitigation_accuracy_report.json - Detailed accuracy test results")
        print("   • json_log_validation_report.json - Log validation analysis")
        print("   • comprehensive_validation_report.json - Complete system assessment")
    
    def run_all_tests(self):
        """Execute complete validation test suite"""
        
        print("🚀 Starting Comprehensive Mitigation System Validation")
        print("Testing Network Security Decision Engine")
        print("=" * 70)
        
        # Phase 1: Mitigation Accuracy Tests
        self.run_mitigation_accuracy_tests()
        time.sleep(1)  # Brief pause between phases
        
        # Phase 2: JSON Log Validation
        self.run_json_log_validation()
        time.sleep(1)  # Brief pause before report
        
        # Generate comprehensive report
        self.generate_comprehensive_report()
        
        print("\n🎉 Comprehensive validation testing completed!")
        print("Review the generated reports for detailed analysis and recommendations.")

def check_prerequisites():
    """Check if required log files exist for validation"""
    
    required_files = [
        '../risk_mitigation_actions.json',
        '../anomaly_log.json'
    ]
    
    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print("⚠️ Warning: Missing log files for validation:")
        for file in missing_files:
            print(f"   • {file}")
        
        print("\n🤖 AUTO-GENERATING TEST DATA...")
        print("Since no existing logs found, creating synthetic test scenarios.")
        
        # Generate synthetic test data
        from synthetic_data_generator import SyntheticDataGenerator
        generator = SyntheticDataGenerator()
        generator.generate_comprehensive_test_data()
        
        print("✅ Synthetic test data generated successfully!")
        return True
    
    print("✅ Found existing log files - using real data for validation")
    return True

def main():
    """Main execution function"""
    
    print("🔬 Comprehensive Mitigation System Test Suite")
    print("Validating Risk-Based Network Security System")
    print("-" * 50)
    
    # Check prerequisites
    if not check_prerequisites():
        print("\n❌ Prerequisites not met. Please generate log files first.")
        print("1. cd .. (go back to controller directory)")
        print("2. ryu-manager ryu_controller.py (run controller to generate logs)")
        print("3. Generate some network traffic")
        print("4. cd validation_tests && python run_validation_tests.py")
        return
    
    # Initialize and run comprehensive tests
    test_runner = ComprehensiveTestRunner()
    test_runner.run_all_tests()

if __name__ == "__main__":
    main()
