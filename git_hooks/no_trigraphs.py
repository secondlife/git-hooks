from __future__ import print_function
import re
import argparse

from .util import eprint


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check that C/C++ files do not contain trigraphs"
    )
    parser.add_argument("filenames", nargs="+", help="Filenames to check")
    args = parser.parse_args(argv)

    trigraphs_present = False
    for filename in args.filenames:
        with open(filename) as f:
            found_trigraphs = re.findall(r"\?\?[=/')!<>-]", f.read())

            if not found_trigraphs:
                continue

            trigraphs_present = True

            found = {}
            for tri in found_trigraphs:
                if tri not in found:
                    found[tri] = 1
                else:
                    found[tri] = found[tri] + 1
            for tri, count in found.items():
                eprint(
                    "{filename}: [{tri}] {count} {occurrence}".format(
                        filename=filename,
                        tri=tri,
                        count=count,
                        occurrence="occurrences" if count > 1 else "occurrence",
                    )
                )
    if trigraphs_present:
        eprint(
            "Commit contains trigraphs, see "
            "https://wiki.secondlife.com/wiki/Coding_Standard#Trigraphs "
            "for details."
        )

    return int(trigraphs_present)


if __name__ == "__main__":
    exit(main())
