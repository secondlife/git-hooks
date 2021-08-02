from __future__ import print_function
import argparse
import re

from .util import eprint


JIRA_PROJECTS = {
    "BUG",
    "DRTVWR",
    "DRTSIM",
    "DRTAPP",
    "DRTDS",
    "DRTDB",
    "DRTCONF",
    "DOC",
    "ESCALATE",
    "SEC",
    "SL",
    "TOOL",
    "WENG",
}


def has_jira_project(msg):
    if "merge" in msg.lower():
        # merges do not need to specify a JIRA
        return 0

    for m in re.finditer(r"([a-zA-Z]+)-(\d+)", msg):
        proj = m.group(1)
        if proj not in JIRA_PROJECTS:
            # Warn about unrecognized project-like strings
            eprint(
                "Commit message has an unrecognized Jira project "
                "{} (in {})".format(proj, m.group())
            )
        else:
            return 0

    eprint("Commit message contains no valid Jira")
    return 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check that files contain a recognized Linden Jira issue")
    parser.add_argument("filename", type=argparse.FileType("r"))
    args = parser.parse_args(argv)
    return has_jira_project(args.filename.read())


if __name__ == "__main__":
    exit(main())
