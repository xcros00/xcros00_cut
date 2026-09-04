#!/usr/bin/env python3
"""
NetCut (Python Edition)
A tool to cut or manage network connections via ARP spoofing.
Ported from NetCut-cli (C++).
"""

import sys
import argparse
from netcut.controller import NetCutController


def main():
    parser = argparse.ArgumentParser(
        description="NetCut (Python) - Ban or recover local network targets via ARP spoofing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                  # Start interactive CLI
  python main.py -i 3.0           # Attack interval 3 seconds
        """
    )
    parser.add_argument(
        "-i", "--interval",
        type=float,
        default=2.0,
        help="ARP attack packet interval in seconds (default: 2.0)"
    )

    args = parser.parse_args()

    controller = NetCutController(attack_interval_s=args.interval)
    controller.initialize()

    print("\n[+] Starting NetCut...")
    print("[+] Press Ctrl+C or enter 'q' anytime to exit and recover all targets.\n")

    try:
        while True:
            controller.show_targets()
            try:
                user_input = input()
            except EOFError:
                break

            keep_running = controller.parse_and_execute_input(user_input)
            if not keep_running:
                break

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user (Ctrl+C). Restoring network for all targets...")
        controller.recover_all_hosts()
        print("[+] All targets restored. Goodbye!")
        sys.exit(0)


if __name__ == "__main__":
    main()
