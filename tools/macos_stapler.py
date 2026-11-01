#!/usr/bin/env python3
"""Retry only observed Apple ticket connection loss; require a successful operation."""

import argparse
import re
import subprocess
import sys
import time


def run(action, path):
    if action not in ('staple', 'validate'):
        raise ValueError('Unsupported stapler action')
    for attempt, delay in enumerate((5, 15, None), 1):
        result = subprocess.run(['xcrun', 'stapler', action, str(path)], capture_output=True, text=True)
        output = result.stdout + result.stderr
        connection_lost = result.returncode == 68 and re.search(r'NSURLErrorDomain Code=-1005\b', output)
        if not connection_lost or delay is None:
            return result
        print(f'Apple ticket connection lost; retrying {action} after {delay}s (attempt {attempt}/3).',
              file=sys.stderr)
        time.sleep(delay)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('staple', 'validate'))
    parser.add_argument('path')
    args = parser.parse_args()
    result = run(args.action, args.path)
    print(result.stdout, end='')
    print(result.stderr, end='', file=sys.stderr)
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())
