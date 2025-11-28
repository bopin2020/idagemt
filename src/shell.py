#!/usr/bin/env python3
"""
Function analysis example for IDA Domain API.

This example demonstrates how to find and analyze functions in an IDA database.
"""

import argparse
from algorithms import *

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
    args = parser.parse_args()
    ctx = Context()
    cp = FuncCodePathAlgo()
    cp.run(ctx)
    cp.get_results()

    #analyze_functions(args.input_file, args.pattern, args.max_results, args.analyze_locals)


if __name__ == '__main__':
    main()
