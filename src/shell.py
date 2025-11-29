#!/usr/bin/env python3
"""
Function analysis example for IDA Domain API.

This example demonstrates how to find and analyze functions in an IDA database.
"""
import argparse
from algorithms import *
from protocols import *

def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description='Function analysis examples')
    parser.add_argument(
        '-f', '--input-file', help='Binary input file to be loaded', type=str, required=True
    )
    parser.add_argument(
        '-p',
        '--pattern',
        default='main',
        help='Pattern to search for in function names (default: main)',
    )
    parser.add_argument(
        '-m',
        '--max-results',
        type=int,
        default=10,
        help='Maximum number of results to display (0 for all, default: 10)',
    )
    parser.add_argument(
        '-l',
        '--analyze-locals',
        action='store_true',
        help='Analyze local variables in functions',
    )
    with Context(parser.parse_args()) as ctx:
        cp = FuncCodePathAlgo()
        cp.run(ctx)
        cp.get_results()

if __name__ == '__main__':
    main()
