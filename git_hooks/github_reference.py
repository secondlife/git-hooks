import argparse
import re
from .util import eprint


def has_valid_github_reference(msg):
    if "merge" in msg.lower():
        # merges do not need to specify an issue
        return 0

    if re.search(r'(?:\w+\/\w+)?#\d+', msg):
        # valid GitHub reference found
        return 0

    eprint("Commit message contains no valid GitHub reference. Please use the format 'secondlife/viewer#1234' or '#1234'")
    return 1

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check that commit message contains valid GitHub reference")
    parser.add_argument("filename", type=argparse.FileType("r"))
    args = parser.parse_args(argv)
    return has_valid_github_reference(args.filename.read())

if __name__ == "__main__":
    exit(main())
