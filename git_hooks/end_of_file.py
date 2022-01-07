import argparse
import os


def fix_file(filename):
    # Get length of file for python 2 seek() which does not support
    # relative arguments.
    stat = os.stat(filename)
    # Empty file
    if stat.st_size == 0:
        return 0
    with open(filename, "rb+") as f:
        f.seek(stat.st_size - 1)
        last_character = f.read(1)
        # last_character will be '' for an empty file
        if last_character not in {b"\n", b"\r"} and last_character != b"":
            # Needs this seek for windows, otherwise IOError
            f.seek(stat.st_size)
            f.write(b"\n")
            return 1

        return 0


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("filenames", nargs="*", help="Filenames to fix")
    args = parser.parse_args(argv)

    retv = 0

    for filename in args.filenames:
        ret_for_file = fix_file(filename)
        if ret_for_file:
            print("Fixing {}".format(filename))
        retv |= ret_for_file

    return retv


if __name__ == "__main__":
    exit(main())
