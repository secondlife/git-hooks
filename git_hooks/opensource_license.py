from __future__ import print_function
import re
import argparse

from .util import eprint


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check that files have an opensource Linden license")
    parser.add_argument("filenames", nargs="*", help="Filenames to check")
    args = parser.parse_args(argv)

    missing_license = False
    for filename in args.filenames:
        with open(filename) as f:
            text = f.read()
            if not re.search(
                r"\$LicenseInfo:[^$]*\blicense=(lgpl|viewerlgpl|bsd|mit)\b",
                text,
                re.IGNORECASE,
            ):
                missing_license = True
                eprint("{}: No opensource license notice".format(filename))
    return missing_license


if __name__ == "__main__":
    exit(main())
