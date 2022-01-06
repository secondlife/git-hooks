from __future__ import print_function
import argparse

from .util import eprint


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check that files have a Linden license"
    )
    parser.add_argument("filenames", nargs="*", help="Filenames to check")
    args = parser.parse_args(argv)

    missing_license = False
    for filename in args.filenames:
        with open(filename) as f:
            if "$License" not in f.read():
                eprint("{}: No license notice".format(filename))
                missing_license = True
    return int(missing_license)


if __name__ == "__main__":
    exit(main())
