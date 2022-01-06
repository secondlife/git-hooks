from __future__ import print_function
import argparse

from .util import eprint


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check files for copyright notice")
    parser.add_argument("filenames", nargs="+", help="Filenames to check")
    args = parser.parse_args(argv)

    missing_copyright = False
    for filename in args.filenames:
        with open(filename) as f:
            if "Copyright" not in f.read():
                eprint("{}: No copyright notice".format(filename))
                missing_copyright = True
    return missing_copyright


if __name__ == "__main__":
    exit(main())
