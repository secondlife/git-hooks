from __future__ import print_function
import argparse
import xml.sax.handler

import llsd

from .util import eprint


class LLSDNotFoundException(Exception):
    pass


class LLSDFoundException(Exception):
    pass


class IsThisLLSD(xml.sax.ContentHandler):
    def startElement(self, name, attrs):
        if name == "llsd":
            raise LLSDFoundException()
        raise LLSDNotFoundException()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("filenames", nargs="*", help="LLSD/XML files to check")
    args = parser.parse_args(argv)

    invalid_llsd = False
    handler = IsThisLLSD()
    for filename in args.filenames:
        # SAX will close this file on exception
        xml_file = open(filename, "rb")
        try:
            xml.sax.parse(xml_file, handler)
        except (xml.sax.SAXException, LLSDNotFoundException):
            # Allow invalid XML to be caught by an XML syntax check
            continue
        except LLSDFoundException:
            with open(filename, "rb") as llsd_file:
                try:
                    llsd.parse(llsd_file.read())
                except Exception as e:
                    eprint("{}: Error parsing llsd, {}".format(filename, e))
                    invalid_llsd = True
    return int(invalid_llsd)


if __name__ == "__main__":
    exit(main())
