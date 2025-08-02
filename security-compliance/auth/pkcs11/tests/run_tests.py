#!/usr/bin/env python3
"""
Test Runner for PKCS#11 Infrastructure

Comprehensive test suite runner for all PKCS#11 infrastructure components.
Provides test discovery, execution, reporting, and coverage analysis.

Author: AI Agent - PKCS#11 Infrastructure Implementation
Date: 2025-07-27
Classification: UNCLASSIFIED
"""

import unittest
import sys
import os
import argparse
import time
from io import StringIO
import json
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ColoredTextTestResult(unittest.TextTestResult):
    """Enhanced test result with colored output"""
    
    def __init__(self, stream, verbosity, use_colors=True):
        super().__init__(stream, verbosity)
        self.use_colors = use_colors and hasattr(stream, 'isatty') and stream.isatty()
        
        # Color codes
        if self.use_colors:
            self.colors = {
                'green': '\033[92m',
                'red': '\033[91m',
                'yellow': '\033[93m',
                'blue': '\033[94m',
                'cyan': '\033[96m',
                'magenta': '\033[95m',
                'reset': '\033[0m'
            }
        else:
            self.colors = {color: '' for color in ['green', 'red', 'yellow', 'blue', 'cyan', 'magenta', 'reset']}
    
    def addSuccess(self, test):
        super().addSuccess(test)
        if self.verbosity > 1:
            self.stream.write(f"{self.colors['green']}✓{self.colors['reset']} ")
            self.stream.flush()
    
    def addError(self, test, err):
        super().addError(test, err)
        if self.verbosity > 1:
            self.stream.write(f"{self.colors['red']}✗{self.colors['reset']} ")
            self.stream.flush()
    
    def addFailure(self, test, err):
        super().addFailure(test, err)
        if self.verbosity > 1:
            self.stream.write(f"{self.colors['red']}✗{self.colors['reset']} ")
            self.stream.flush()
    
    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        if self.verbosity > 1:
            self.stream.write(f"{self.colors['yellow']}⚠{self.colors['reset']} ")
            self.stream.flush()


class EnhancedTestRunner(unittest.TextTestRunner):
    """Enhanced test runner with better reporting"""
    
    def __init__(self, verbosity=2, use_colors=True, **kwargs):
        self.use_colors = use_colors
        super().__init__(verbosity=verbosity, **kwargs)
    
    def _makeResult(self):
        return ColoredTextTestResult(self.stream, self.verbosity, self.use_colors)
    
    def run(self, test):
        """Run the test suite with enhanced reporting"""
        start_time = time.time()
        
        # Print header
        self._print_header()
        
        # Run tests
        result = super().run(test)
        
        # Calculate duration
        duration = time.time() - start_time
        
        # Print summary
        self._print_summary(result, duration)
        
        return result
    
    def _print_header(self):
        """Print test run header"""
        colors = self.colors if hasattr(self, 'colors') else {color: '' for color in ['cyan', 'reset']}
        
        header = f"""
{colors['cyan']}{'='*70}
PKCS#11 Infrastructure Test Suite
{'='*70}{colors['reset']}
"""
        self.stream.write(header)
        self.stream.flush()
    
    def _print_summary(self, result, duration):
        """Print test run summary"""
        if self.use_colors:
            colors = {
                'green': '\033[92m',
                'red': '\033[91m',
                'yellow': '\033[93m',
                'cyan': '\033[96m',
                'reset': '\033[0m'
            }
        else:
            colors = {color: '' for color in ['green', 'red', 'yellow', 'cyan', 'reset']}
        
        total_tests = result.testsRun
        errors = len(result.errors)
        failures = len(result.failures)
        skipped = len(result.skipped)
        passed = total_tests - errors - failures - skipped
        
        # Determine overall status
        if errors > 0 or failures > 0:
            status_color = colors['red']
            status = "FAILED"
        elif skipped > 0:
            status_color = colors['yellow']
            status = "PASSED (with skipped)"
        else:
            status_color = colors['green']
            status = "PASSED"
        
        summary = f"""
{colors['cyan']}{'='*70}
Test Summary
{'='*70}{colors['reset']}

Total Tests: {total_tests}
{colors['green']}Passed: {passed}{colors['reset']}
{colors['red']}Failed: {failures}{colors['reset']}
{colors['red']}Errors: {errors}{colors['reset']}
{colors['yellow']}Skipped: {skipped}{colors['reset']}

Duration: {duration:.2f} seconds
Status: {status_color}{status}{colors['reset']}

{colors['cyan']}{'='*70}{colors['reset']}
"""
        
        self.stream.write(summary)
        self.stream.flush()


def discover_tests(test_dir=None, pattern='test_*.py'):
    """
    Discover test modules
    
    Args:
        test_dir: Directory to search for tests
        pattern: Test file pattern
    
    Returns:
        TestSuite containing discovered tests
    """
    if test_dir is None:
        test_dir = os.path.dirname(os.path.abspath(__file__))
    
    loader = unittest.TestLoader()
    suite = loader.discover(test_dir, pattern=pattern)
    
    return suite


def run_specific_test(test_name):
    """
    Run a specific test by name
    
    Args:
        test_name: Name of test module or test case
    
    Returns:
        TestResult
    """
    loader = unittest.TestLoader()
    
    # Try to load as module first
    try:
        suite = loader.loadTestsFromName(test_name)
    except (ImportError, AttributeError):
        # Try to load as test case
        try:
            suite = loader.loadTestsFromName(f"test_{test_name}")
        except (ImportError, AttributeError):
            print(f"Could not find test: {test_name}")
            return None
    
    runner = EnhancedTestRunner()
    return runner.run(suite)


def run_module_tests(module_name):
    """
    Run tests for a specific module
    
    Args:
        module_name: Name of module to test
    
    Returns:
        TestResult
    """
    test_module_name = f"test_{module_name}"
    
    try:
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromName(test_module_name)
        
        runner = EnhancedTestRunner()
        return runner.run(suite)
        
    except ImportError as e:
        print(f"Could not import test module {test_module_name}: {e}")
        return None


def generate_test_report(result, output_file=None):
    """
    Generate comprehensive test report
    
    Args:
        result: TestResult object
        output_file: Optional file to write report to
    
    Returns:
        Report dictionary
    """
    report = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'summary': {
            'total_tests': result.testsRun,
            'passed': result.testsRun - len(result.errors) - len(result.failures),
            'failed': len(result.failures),
            'errors': len(result.errors),
            'skipped': len(result.skipped)
        },
        'failures': [],
        'errors': [],
        'skipped': []
    }
    
    # Add failure details
    for test, traceback in result.failures:
        report['failures'].append({
            'test': str(test),
            'traceback': traceback
        })
    
    # Add error details
    for test, traceback in result.errors:
        report['errors'].append({
            'test': str(test),
            'traceback': traceback
        })
    
    # Add skipped details
    for test, reason in result.skipped:
        report['skipped'].append({
            'test': str(test),
            'reason': reason
        })
    
    # Write to file if specified
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
    
    return report


def main():
    """Main test runner entry point"""
    parser = argparse.ArgumentParser(
        description='PKCS#11 Infrastructure Test Runner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Run all tests
  %(prog)s --module pkcs11_wrapper  # Run wrapper tests only
  %(prog)s --test test_initialization # Run specific test
  %(prog)s --verbose --no-color     # Run with verbose output, no colors
  %(prog)s --report results.json    # Generate JSON report
        """
    )
    
    parser.add_argument(
        '--module', '-m',
        help='Run tests for specific module (e.g., pkcs11_wrapper, communication, error_handler)'
    )
    
    parser.add_argument(
        '--test', '-t',
        help='Run specific test by name'
    )
    
    parser.add_argument(
        '--pattern', '-p',
        default='test_*.py',
        help='Test file pattern (default: test_*.py)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )
    
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    parser.add_argument(
        '--report', '-r',
        help='Generate JSON test report to file'
    )
    
    parser.add_argument(
        '--list-tests',
        action='store_true',
        help='List available tests without running them'
    )
    
    args = parser.parse_args()
    
    # Set verbosity
    verbosity = 2 if args.verbose else 1
    
    # Configure colors
    use_colors = not args.no_color
    
    if args.list_tests:
        # List available tests
        suite = discover_tests(pattern=args.pattern)
        print("Available Tests:")
        print("================")
        
        def print_test(test):
            if hasattr(test, '_tests'):
                for subtest in test._tests:
                    print_test(subtest)
            else:
                print(f"  {test}")
        
        print_test(suite)
        return 0
    
    # Run specific test or module
    if args.test:
        result = run_specific_test(args.test)
    elif args.module:
        result = run_module_tests(args.module)
    else:
        # Run all tests
        suite = discover_tests(pattern=args.pattern)
        runner = EnhancedTestRunner(verbosity=verbosity, use_colors=use_colors)
        result = runner.run(suite)
    
    if result is None:
        return 1
    
    # Generate report if requested
    if args.report:
        generate_test_report(result, args.report)
        print(f"\nTest report written to: {args.report}")
    
    # Return appropriate exit code
    if result.errors or result.failures:
        return 1
    else:
        return 0


if __name__ == '__main__':
    sys.exit(main())