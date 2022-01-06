from __future__ import print_function
import argparse

from .util import eprint


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check that files only indent with tabs"
    )
    parser.add_argument("filenames", nargs="+", help="Filenames to check")
    args = parser.parse_args(argv)

    found_spaces = False
    for filename in args.filenames:
        count = 0
        with open(filename) as f:
            for line in f.readlines():
                if line.startswith(" "):
                    count += 1
            if count > 0:
                found_spaces = True
                eprint(
                    "{filename}: {count} {lines} starting with spaces found".format(
                        filename=filename,
                        count=count,
                        lines="lines" if count > 1 else "line",
                    )
                )

    return int(found_spaces)


if __name__ == "__main__":
    exit(main())
