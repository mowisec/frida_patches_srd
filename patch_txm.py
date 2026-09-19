#!/usr/bin/env python3
"""Command-line entry point: see srdpatch/cli/txm.py for what it does.

This shim exists so the tool can be run straight out of a checkout, without
installing anything:  python3 patch_txm.py <txm-payload> <patch> -o <out>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from srdpatch.cli.txm import main       # noqa: E402  (after the path fix)

if __name__ == "__main__":
    sys.exit(main())
