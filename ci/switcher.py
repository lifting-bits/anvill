#!/usr/bin/env python3
import sys

from binaryninja.update import UpdateChannel, set_auto_updates_enabled, is_update_installation_pending, install_pending_update
from binaryninja import core_version
import argparse

chandefault = list(UpdateChannel)[0].name
channel = None
versions = []


def main():
    prs = argparse.ArgumentParser("Binja Version Switcher")
    prs.add_argument('--version_string', type=str)
    prs.add_argument('channel_string', metavar='C', type=str)

    args = prs.parse_args()

    channel = UpdateChannel[args.channel_string]

    if args.channel_string is None:
        channel.update_to_latest()
    else:
        set_auto_updates_enabled(False)
        for v in channel.versions:
            if args.version_string in v.version:
                print("Updating...")
                v.update()
                if is_update_installation_pending():
                    install_pending_update()
                return


if __name__ == "__main__":
	main()
