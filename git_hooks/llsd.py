from __future__ import print_function
import argparse
from xml.etree import ElementTree

from llbase import llsd

from .util import eprint


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("filenames", nargs="*", help="Filenames to check")
    args = parser.parse_args(argv)

    invalid_llsd = False
    for filename in args.filenames:
        with open(filename) as f:
            text = f.read()
            try:
                root = ElementTree.fromstring(text)
            except ElementTree.ParseError:
                # Allow invalid XML to be caught by XML check
                continue

            if root.tag != "llsd":
                continue

            try:
                llsd.parse(text.encode())
            except Exception as e:
                eprint("{}: Error parsing llsd, {}".format(filename, e))
                invalid_llsd = True
    return int(invalid_llsd)


if __name__ == "__main__":
    exit(main())
