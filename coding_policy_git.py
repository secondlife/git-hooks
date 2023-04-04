#!/usr/bin/env python

"""\
This script is used for checking commits and files against the Linden coding policy.

To use with git commit hooks:
- From your repo, run the git-hooks/install script. This will create pre-commit and commit-msg hooks that refer to this script.
- Install any necessary python modules via pip. "pip -r git-hooks/requirements.txt" should pick up any that are needed.
- Run "git commit" as usual.

To use to check some or all files manually:
coding_policy_git.py [--policy opensource|proprietary] [--pre-commit] [--all_files] [file...]
--policy specifies the policy to use. Defaults to opensource. If not specified by by --policy and a .git_hooks_policy file is found in repo root, we will use the contents of that as the policy.
--all_files will check all managed files in the current working tree
Any arguments at the end are treated as individual file names to check
"""
from __future__ import print_function

license = """\

$LicenseInfo:firstyear=2020&license=viewerlgpl$
Second Life Viewer Source Code
Copyright (C) 2020, Linden Research, Inc.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation;
version 2.1 of the License only.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

Linden Research, Inc., 945 Battery Street, San Francisco, CA  94111  USA
$/LicenseInfo$
"""

import os
import sys
try:
    from git import Repo, Git # requires the gitpython package
except ImportError:
    print("this script requires the gitpython package")
    sys.exit(1)

import argparse
import chardet
import itertools
from pathlib import Path
import re
import subprocess

# From mercurial.utils.stringutil. This is not a great binary checker
# but seems to work well enough in our environment.
def binary(s):
    """return true if a string is binary data"""
    # in Python 3, 'in' requires same type on both sides: bytes or str
    return bool(s) and ((b'\0' if isinstance(s, bytes) else '\0') in s)

# ANSI escape sequences for colored text, from https://stackoverflow.com/questions/287871
class bcolors(object):
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# From coding_policy.py

failure_message = '''
** For details of the Linden Lab coding standards and how to
** fix the problems with your changes, please refer to
** https://wiki.secondlife.com/wiki/Coding_Standard
'''
success_message = 'Coding policies PASS\n'

checking_message = 'Checking Linden Lab %s coding policies...\n'
not_checking_message = 'This repo is not subject to Linden Lab coding policy checks\n'

# --------------------------- Policy check helpers ---------------------------
def rx(regexp):
    """
    Given regular expression 'regexp', compile it and return a
    predicate(string) function that returns whether that string matches the
    compiled regexp. The re.search() function is used, which means the match
    is not anchored, which means the regexp need not start with '.*'. To
    anchor the match to the start of the string, prepend '^' to your regexp.

    Intended usage is for the predicate argument of the validation decorator.
    If the predicate you want is to match the pathname of the file being tested
    against a particular regexp, pass rx(r'your regexp') as the callable.
    """
    compiled = re.compile(regexp, re.IGNORECASE)
    # return the compiled regexp's search() method
    return compiled.search

def raw(data_bytes, **kwds):
    """
    no-op decoder for validations that want raw binary data from file
    """
    return data_bytes

def maybe_text(data_bytes, **kwds):
    """
    decoder for use when a file might be binary or might be text in some
    encoding yet to be determined

    n.b. If a decoder returns None, checker.check_file() skips the policy
    function call.
    """
    if binary(data_bytes):
        # if we already think it's a binary file, don't bother trying to decode
        return None

    try:
        # chardet makes guesses -- sometimes it guesses wrong about files we
        # know should be UTF-8
        return data_bytes.decode('utf8')
    except UnicodeDecodeError as err:
        pass

    # UTF-8 didn't work, let chardet take a swing at it
    coding = chardet.detect(data_bytes)
    if not coding['encoding']:
        # if chardet can't figure out what kind of file it is, probably binary
        return None
    # but if chardet thinks it has figured out the encoding, try that
    return data_bytes.decode(coding['encoding'], **kwds)

def utf8(data_bytes, **kwds):
    """
    UTF-8 decoder for validations that want ordinary decoded text

    n.b. the 'utf8' codec leaves '\r\n' unchanged, unlike open(mode='r')
    """
    return data_bytes.decode('utf8', **kwds)

def utf16(data_bytes, **kwds):
    """
    UTF-16 decoder for validations against UTF16 files, e.g. NSIS source

    n.b. the 'utf16' codec knows enough to skip initial BOM header bytes
    """
    return data_bytes.decode('utf16', **kwds)

class validation(object):
    """
    Decorator to register a validation function in a particular policy
    collection with a particular predicate function.

    Example usage:

    @validation(common_policies, rx(r'\.xml$'))
    def valid_xml(path, data):
        ...

    registers valid_xml() in the common_policies list with a predicate
    function that matches the file's pathanme against the specified regular
    expression.

    Also pass (e.g.) decoder=raw or decoder=utf16 for validation functions
    that want the file data in some alternative form.
    """
    def __init__(self, policies, predicate, decoder=utf8):
        self.policies  = policies
        self.predicate = predicate
        self.decoder   = decoder

    def __call__(self, func):
        # each policies list consists of (predicate, decoder, function) triples
        self.policies.append((self.predicate, self.decoder, func))
        return func

# ------------------------- Policy check registries --------------------------
common_policies = []
proprietary_policies = []
opensource_policies = []

# ================ Start of rule selector methods ================

def is_windows_only_file(name) :
    return (name.endswith('.bat')
            or name.endswith('.vcxproj')
            or name.endswith('.sln')
            or re.search('/(windows|vstool)/', name)
            )

def last_line_should_have_eol(name) :
    return re.search(r'.*\.(?:cpp|[ch]|py|glsl|cmake|txt)$', name) \
           and not name.endswith('.lproj/language.txt')

# ================ End of rule selector methods ================

# ================ Start of policy check methods ================

@validation(common_policies, lambda p: not is_windows_only_file(p), decoder=maybe_text)
def unix_line_endings(path, data):
    if '\r\n' in data:
        yield 'Windows line endings found'

@validation(common_policies, is_windows_only_file, decoder=maybe_text)
def windows_line_endings(path, data):
    if re.search('(?<!\r)\n', data, re.MULTILINE):
        yield 'Unix line endings found'

@validation(common_policies, rx(r'\.(?:cpp|[ch]|py|glsl)$'))
def copyright_needed(path, data):
    if 'Copyright' not in data:
        yield 'no copyright notice'

@validation(common_policies, rx(r'\.(?:cpp|[ch])$'))
def no_trigraphs(path, data):
    found_trigraphs=re.findall(r"\?\?[=/')!<>-]", data)
    if found_trigraphs:
        found={}
        for tri in found_trigraphs:
            if tri not in found:
                found[tri] = 1
            else:
                found[tri] = found[tri] + 1
        details=""
        for tri, occurs in found.items():
            if occurs == 1:
                details=details + "\n [%s] 1 occurrence" % tri
            else:
                details=details + "\n [%s] %d occurrences" % (tri, occurs)
        yield 'contains trigraph; see https://wiki.secondlife.com/wiki/Coding_Standard#Trigraphs'+details

@validation(proprietary_policies, rx(r'\.(?:cpp|[ch]|py|glsl|sh|bat|pl)$'))
def license_needed(path, data):
    if '$License' not in data:
        yield 'no license notice'

@validation(opensource_policies, rx(r'\.(?:cpp|[ch]|py|glsl)$'))
def open_license_needed(path, data):
    if not re.search(r"\$LicenseInfo:[^$]*\blicense=(lgpl|viewerlgpl|bsd|mit)\b", data, re.IGNORECASE):
        yield 'no open source license notice'

@validation(common_policies, rx(r'(?:\.(?:py|cmake)|CMakeLists.txt)$'))
def tabs_forbidden(path, data):
    if '\t' not in data:
        return
    found=0
    for line in data.splitlines():
        if '\t' in line:
            found += 1
    yield '%d lines with tab characters found' % found

@validation(common_policies, rx(r'(^[Mm]akefile|\.make)$'))
def leading_tabs_required(path, data):
    any_leading_space = r'^\t* +\t*'
    if any_leading_space not in data:
        return
    i = 1
    for line in data.splitlines():
        if re.match(any_leading_space, line) is not None:
            yield i, 'spaces found instead of tab'
        i += 1

# Mercurial-specific, not clear whether it needs to be handled with git
def windows_friendly_path(path, data):
    if re.search('^.hg',path) :
        # Mercurial takes care of these on its own
        return
    lpath = path.lower()
    if hasattr(store,'_auxencode') :
        # hg > 1.6
        # Note: as of this changelist for the mercurial API:
        # http://www.selenic.com/repo/hg/rev/81a033bb29bc, which was part of HG 2.4,
        # _auxencode accepts an array of strings (the path 'parts') and returns the
        # same.  This change was apparently not publicly documented, but since we're
        # actually using a "private" method, it's really not their issue.
        if hasattr(store, "_winres3"):
            # hg >= 2.4
            rpath = '/'.join(store._auxencode(lpath.split('/'), True))
        else:
            # hg 1.6 < r < 2.4
            rpath = store._auxencode(lpath,True)
    else :
        # hg <= 1.6
        rpath = store.auxencode(lpath)
    if rpath != lpath:
        yield 'pathname is not safe for use on Windows systems ("%s" vs "%s")' % (rpath,lpath)

@validation(common_policies, last_line_should_have_eol)
def last_line_ends_with_eol(path, data):
    if data and data[-1] != '\n':
        yield 'last line does not end with EOL'

@validation(common_policies, rx(r'\.xml$'), decoder=raw)
def valid_xml(path, data):
    import xml.etree.ElementTree as parser
    # We don't yet try to validate against a DTD, merely to ensure
    # that an XML file isn't completely insane.
    try :
        root = parser.fromstring(data)
    except parser.ParseError as parse_error :
       yield 'invalid XML: %s' % parse_error.msg 

# llsd.parse() expects bytes, not str
@validation(common_policies, rx(r'\.xml$'), decoder=raw)
def valid_llsd(path, data):
    import xml.etree.ElementTree as parser
    try :
        root = parser.fromstring(data)
    except Exception as parse_error :
        return # don't duplicate the error from the valid_xml hook
    if root.tag == 'llsd':
        try:
            from llbase import llsd
        except ImportError:
            yield "this hook requires llsd from the llbase python package"
            return
        try:
            llsd.parse(data)
        except Exception as e:
            yield "error parsing llsd: %s\n" % e

# ================ End of policy check methods ================


# ================ Start of policy control variables ================

# maps the --policy argument, or third column of the repo_roots table below,
# to one of the policy lists above
policy_map = {
    'proprietary' : proprietary_policies + common_policies,
    'opensource' : opensource_policies + common_policies,
    }

# (Following is old hg-based code, not currently supported)
#
# We identify a repository that is subject to checking by whitelist,
# based on the ID of the first changeset in that repository.  Here's a
# simple way to obtain the necessary changeset ID:
#
#   hg log -r0 --template '{node}\n'
#
# Note that this lookup can be overridden (see repo_policy_name below)
repo_roots = (
    # format: ('helpful description', 'changeset ID', 'policy')

    # FIXME: hg repos. Won't work as-is, need to update the ids once these are ported
    ('autobuild', '150af56aeda147f2bcaf2058cc591446c62a60b1', 'opensource'),
    ('convexdecomposition', '15eca2f72654f693292c0473b910d0b75f5c63e8', 'proprietary'),
    ('convexdecompositionstub', '4522adf7908d480e4773be7811429419c951fac8', 'opensource'),
    ('internal indra', '01da24a6ed088e1519f98a56f03bf7e5d270a552', 'proprietary'),
    ('viewer-development', '003dd9461bfa479049afcc34545ab3431b147c7c', 'opensource'),
    ('llphysicsextensions', '8b92acd6e747b81af331159b36e7ae91c7725f59', 'proprietary'),

    # git repos
    ('indra-server', '137f6caec9396a8bae02ec421e14106fb7232338', 'proprietary'),
    ('viewer', '420b91db29485df39fd6e724e782c449158811cb', 'opensource'),
    )

# ================ End of policy control variables ================

# checker - this class actually runs each applicable policy check
class checker(object):
    def __init__(self, ui, tip, policies):
        self.ui = ui
        self.tip = tip
        self.policies = policies
        self.violations = 0
        self.seen = set()
    
    def check_file(self, f, data) :
        # 'data' is bytes
        self.ui.debug('  checking %s' % f)

        # Typically, more than one policy function specifies the same decoder.
        # Cache decoded results here so we don't have to keep passing 'data'
        # through the same decoder function over and over again. (See also
        # functools.lru_cache, available only in Python 3.)
        cache = {}

        for predicate, decoder, policy in self.policies:
            name = policy.__name__
            # predicate is a callable
            if not predicate(f.lower()):
                continue

            decode_errs = []
            # have we already run this decoder?
            try:
                decoded = cache[decoder.__name__]
            except KeyError:
                try:
                    decoded = decoder(data)
                except Exception as err:
                    # If we can't decode file content according to the policy
                    # function's specified decoder, capture that error.
                    decode_errs = [(f, ('%s: %s' % (err.__class__.__name__, err)))]
                    # but then retry, suppressing the error so we can still
                    # run the policy check
                    decoded = decoder(data, errors='replace')

                # either way, cache result for subsequent uses of same decoder
                cache[decoder.__name__] = decoded

            # 'decoded' might be None, meaning the decoder says to skip the
            # policy function
            generator = policy(f, decoded) if decoded else []

            self.ui.debug('    '+name)
            for violation in itertools.chain(decode_errs, generator):
                # Doesn't work with git; commit message not known during pre-commit check.
                #magic = 'warn-on-failure:' + name
                #warning = magic in desc
                self.violations += 1
                try:
                    line, violation = violation
                    msg = '%s:%d: %s' % (f, line, violation)
                except (TypeError, ValueError):
                    msg = '%s: %s' % (f, violation)
                if not msg.endswith('\n'):
                    msg += '\n'
                self.ui.warn(msg)

    def check_files(self, files):
        for f in files:
            try:
                # certain validations require reading the file as binary --
                # for instance, we can't detect '\r\n' line endings in text
                # mode ("r") because Python maps all such to plain '\n'
                with open(f,"rb") as fh:
                    data = fh.read()
            except Exception as err:
                self.ui.note("unable to read file %s: %s: %s" %
                             (f, err.__class__.__name__, err))
            else:
                self.check_file(f, data)
                
    def check_commit_msg(self, msg):
        # check for valid JIRA links
        found_jira = False
        if "merge" in msg.lower():
            # merges do not need to specify a JIRA
            return
        for m in re.finditer(r'([a-zA-Z]+)-(\d+)', msg):
            proj = m.group(1).upper()
            if not proj in valid_jira_projects:
                self.ui.warn("Commit message has unrecognized JIRA project %s (in %s)" % (proj, m.group()))
                self.violations += 1
            else:
                found_jira = True
        if not found_jira:
            self.ui.warn("Commit message contains no valid JIRAs")
            self.violations += 1

    def done(self):
        if self.violations:
            self.ui.warn("%d violations found" % (self.violations))
            self.ui.status(failure_message)
        else:
            self.ui.status(success_message)
        return self.violations

class checker_ui(object):
    def __init__(self):
        self.debug_flag = False
        pass
    def note(self,s):
        print(s)
    def debug(self,s):
        if self.debug_flag:
            print(s)
    def warn(self,s):
        print(bcolors.WARNING + s + bcolors.ENDC)
    def status(self,s):
        print(s)

def pre_commit_check(repo, ui, checker, policies):
    for d in repo.index.diff(repo.head.commit):
        if d.change_type in ['A','M', 'R']: # skip 'D' for delete
            filename = d.a_path
            blob = d.a_blob
            if blob is not None:
                data = blob.data_stream.read()
                checker.check_file(filename, data)
    checker.done()

valid_jira_projects = "BUG,DRTVWR,DRTSIM,DRTAPP,DRTDS,DRTDB,DRTCONF,DOC,ESCALATE,SEC,SL,TOOL,WENG".split(",")

def usage():
    print(__doc__)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Linden coding policy checks")
    parser.add_argument("--pre-commit", action="store_true")
    parser.add_argument("--commit-msg")
    parser.add_argument("-d","--debug", action="store_true", default=False)
    parser.add_argument("--all_files", action="store_true")
    parser.add_argument("--policy")
    parser.add_argument("--usage", action="store_true")
    parser.add_argument("files", nargs="*")
    args = parser.parse_args()

    if args.debug:
        print("this is coding_policy_git", "args", sys.argv)

    if args.usage:
        usage()
        sys.exit(0)

    # find root of current repo
    cwd = os.getcwd()
    rootdir = Git(cwd).rev_parse("--show-toplevel")
    # Bug in gitpython git.Git? On a cygwin system, 'rootdir' might be
    # something like '\cygdrive\d\work\Viewer\viewer_W64\latest'. This raises
    # NoSuchPathError when passed to git.Repo below. Try to de-cygwinify.
    rootdir = Path(rootdir)
    # Use slice notation because if rootdir happens to be (e.g.) 'C:\',
    # rootdir.parts[1] raises IndexError, while [1:2] returns ().
    # ('parts' is documented to be a tuple.)
    if rootdir.parts[1:2] == ('cygdrive',):
        # The odd path string quoted above is neither fish nor fowl: it is NOT
        # a proper cygwin path, and cygpath doesn't recognize it as such,
        # erroneously returning 'C:/cygdrive/d/work/Viewer/viewer_W64/latest'.
        # Only if we pass '/cygdrive/d/work/Viewer/viewer_W64/latest' does
        # cygpath recognize it and perform proper conversion.
        rootfixed = subprocess.run(['cygpath', '-m', rootdir.as_posix()],
                                   encoding='utf8', check=True,
                                   stdout=subprocess.PIPE).stdout.rstrip()
        print(f'Fixing cygwin {rootdir} to {rootfixed}')
        rootdir = Path(rootfixed)
    repo = Repo(str(rootdir))

    ui = checker_ui()
    ui.debug_flag = args.debug

    policy_name = None
    if args.policy:
        policy_name = args.policy
    if not policy_name:
        # check for .git_hooks_policy in repo root
        policy_file = Path(repo.working_tree_dir)/".git_hooks_policy"
        if policy_file.is_file():
            try:
                with open(policy_file,"r") as fh:
                    policy_name = fh.readline().split()[0]
                    print("read policy_name", policy_name)
            except (IOError, OSError) as err:
                print("Unable to read policy name from '%s': %s: %s" %
                      (policy_file, err.__class__.__name__, err))
    if not policy_name:
        # check for known repo using commit id
        for (name, commit_id, policy) in repo_roots:
            try:
                commit = repo.rev_parse(commit_id)
                print("match for name", name, "policy is", policy)
                policy_name = policy
            except:
                pass
    if not policy_name:
        print("no policy name found, assuming opensource")
        policy_name = "opensource"

    try:
        policies = policy_map[policy_name]
    except KeyError:
        ui.warn("unrecognized policy %s, known policies are: %s" %
                (policy_name, ", ".join(policy_map)))
        sys.exit(1)

    if args.pre_commit:
        commit_checker = checker(ui, None, policies)
        pre_commit_check(repo, ui, commit_checker, policies)
        if commit_checker.violations:
            ui.warn("pre-commit check failed")
            sys.exit(1)

    if args.commit_msg:
        ui.debug("commit-msg check, file %s" % args.commit_msg)
        msg_checker = checker(ui, None, policies)
        with open(args.commit_msg,"r") as fh:
            msg = fh.read()
            msg_checker.check_commit_msg(msg)
            errs = msg_checker.done()
            if errs:
                ui.warn("commit-msg check failed")
                sys.exit(1)

    if args.all_files:
        # check all managed files in the current working tree
        ui.note("checking all managed files")
        g = Git(str(rootdir))
        files = g.ls_files().split("\n")
        files = [str(rootdir / f) for f in files]
        file_checker = checker(ui, None, policies)
        file_checker.check_files(files)
        file_checker.done()
        if file_checker.violations:
            ui.warn("--all_file check violations found: %d" % (file_checker.violations))
            sys.exit(1)

    if args.files:
        ui.note("checking files from command line " + ", ".join(args.files))
        file_checker = checker(ui, None, policies)
        file_checker.check_files(args.files)
        file_checker.done()
        if file_checker.violations:
            ui.warn("file check violations found: %d" % (file_checker.violations))
            sys.exit(1)
