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
except:
    print("this script requires the gitpython package")
    sys.exit(1)
    
import re
import argparse

# From mercurial.utils.stringutil. This is not a great binary checker
# but seems to work well enough in our environment.
def binary(s):
    """return true if a string is binary data"""
    return bool(s and b'\0' in s)

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

# ================ Start of policy check methods ================

def unix_line_endings(path, data):
    if not binary(data) and '\r\n' in data:
        yield 'Windows line endings found'

def windows_line_endings(path, data):
    if not binary(data) and re.search('(?<!\r)\n', data, re.MULTILINE):
        yield 'Unix line endings found'

def copyright_needed(path, data):
    if 'Copyright' not in data:
        yield 'no copyright notice'

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

def license_needed(path, data):
    if '$License' not in data:
        yield 'no license notice'

def open_license_needed(path, data):
    if not re.search(r"\$LicenseInfo:[^$]*\blicense=(lgpl|viewerlgpl|bsd|mit)\b", data, re.IGNORECASE):
        yield 'no open source license notice'

def tabs_forbidden(path, data):
    if '\t' not in data:
        return
    found=0
    for line in data.splitlines():
        if '\t' in line:
            found += 1
    yield '%d tab characters found' % found

def leading_tabs_required(path, data):
    any_leading_space = r'^\t* +\t*'
    if any_leading_space not in data:
        return
    i = 1
    for line in data.splitlines():
        if re.match(any_leading_space, line) is not None:
            yield i, 'spaces found instead of tab'
        i += 1

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

def last_line_ends_with_eol(path, data):
    if data and data[-1] != '\n':
        yield 'last line does not end with EOL'

def valid_xml(path, data):
    import xml.etree.ElementTree as parser
    # We don't yet try to validate against a DTD, merely to ensure
    # that an XML file isn't completely insane.
    try :
        root = parser.fromstring(data)
    except parser.ParseError as parse_error :
       yield 'invalid XML: %s' % parse_error.msg 

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

common_policies = (
    # format:
    # ('policy name', 'regexp to match path against', policy_checking_function)
    ('copyright', r'.*\.(?:cpp|[ch]|py|glsl)$', copyright_needed),
    ('no-trigraphs', r'.*\.(?:cpp|[ch])$', no_trigraphs),
    ('eol-at-eof', lambda p: last_line_should_have_eol(p), last_line_ends_with_eol),
    ('no-tabs', r'.*(?:\.(?:py|cmake)|CMakeLists.txt)$', tabs_forbidden),
    ('require-leading-tabs', r'^([Mm]akefile|.*\.make)$', leading_tabs_required),
    ('valid-xml', r'.*\.xml$', valid_xml),
    ('valid-llsd', r'.*\.xml$', valid_llsd),
    # Mercurial-specific, not clear whether it needs to be handled with git
    #('windows-path', r'', windows_friendly_path), 
    ('unix-eol', lambda p: not is_windows_only_file(p), unix_line_endings),
    ('windows-eol', lambda p: is_windows_only_file(p), windows_line_endings),
    )

proprietary_policies = (
    # format:
    # ('policy name', 'regexp to match path against', policy_checking_function)
    ('license', r'.*\.(?:cpp|[ch]|py|glsl|sh|bat|pl)$', license_needed),
    ) + common_policies

opensource_policies = (
    # format:
    # ('policy name', 'regexp to match path against', policy_checking_function)
    ('open-license', r'.*\.(?:cpp|[ch]|py|glsl)$', open_license_needed),
    ) + common_policies

# maps the --policy argument, or third column of the repo_roots table below,
# to one of the policy lists above
policy_map = {
    'proprietary' : proprietary_policies,
    'opensource' : opensource_policies
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
    ('hg-tools', 'c3a2af7065cfdf857798e47ae741fb41c13ceb1d', 'opensource'),
    ('autobuild', '150af56aeda147f2bcaf2058cc591446c62a60b1', 'opensource'),
    ('convexdecomposition', '15eca2f72654f693292c0473b910d0b75f5c63e8', 'proprietary'),
    ('convexdecompositionstub', '4522adf7908d480e4773be7811429419c951fac8', 'opensource'),
    ('internal indra', '01da24a6ed088e1519f98a56f03bf7e5d270a552', 'proprietary'),
    ('viewer-development', '003dd9461bfa479049afcc34545ab3431b147c7c', 'opensource'),
    ('llphysicsextensions', '8b92acd6e747b81af331159b36e7ae91c7725f59', 'proprietary'),
    )

# ================ End of policy control variables ================

# ================ Start of rule selector methods ================

def is_windows_only_file(name) :
    if name.endswith('.bat') \
       or name.endswith('.vcxproj') \
       or name.endswith('.sln') \
       or re.search('/(windows|vstool)/', name) \
       :
        return True
    else :
        return False

def last_line_should_have_eol(name) :
    return re.search(r'.*\.(?:cpp|[ch]|py|glsl|cmake|txt)$', name) \
           and not name.endswith('.lproj/language.txt')

# ================ End of rule selector methods ================

# checker - this class actually runs each applicable policy check
class checker(object):
    def __init__(self, ui, tip, policies):
        self.ui = ui
        self.tip = tip
        self.policies = policies
        self.violations = 0
        self.seen = set()
    
    def check_file(self, f, data) :
        self.ui.debug('  checking %s\n' % f)
        for name, pat, policy in self.policies:
            try:
                # pattern is a regular expression
                if not re.match(pat, f, re.IGNORECASE):
                    continue
            except TypeError:
                # pattern is a callable
                if not pat(f.lower()):
                    continue
            self.ui.debug('    '+name+'\n')
            for violation in policy(f, data):
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
                with open(f,"rb") as fh:
                    data = fh.read()
                    self.check_file(f, data)
            except:
                self.ui.note("unable to read file %s" % (f))
                
    def check_commit_msg(self, msg):
        # check for valid JIRA links
        found_jira = False
        status = 0
        for m in re.finditer(r'([a-zA-Z]+)-(\d+)', msg):
            proj = m.group(1).upper()
            if not proj in valid_jira_projects:
                self.ui.warn("Commit message has unrecognized JIRA project %s (in %s)" % (proj, m.group()))
                self.violations += 1
                status = 1
            else:
                found_jira = True
        if not found_jira:
            self.ui.warn("Commit message contains no valid JIRAs")
            status = 1
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
            data = d.a_blob.data_stream.read()
            change_type = d.change_type
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
    repo = Repo(rootdir)

    ui = checker_ui()
    ui.debug_flag = args.debug

    # TODO get policy automatically
    policy_name = 'opensource'
    if args.policy:
        policy_name = args.policy
    else:
        # check for .git_hooks_policy in repo root
        policy_file = os.path.join(repo.working_tree_dir,".git_hooks_policy")
        if os.path.isfile(policy_file):
            try:
                with open(policy_file,"r") as fh:
                    policy_name = fh.readline().split()[0]
                    print("read policy_name", policy_name)
            except:
                print("Unable to read policy name from", policy_file)

    if policy_name not in policy_map:
        ui.warn("unrecognized policy %s, known policies are: %s" % (args.policy, ", ".join(policy_map)))
        sys.exit(1)

    policies = policy_map[policy_name]

    if args.pre_commit:
        commit_checker = checker(ui, None, policies)
        pre_commit_check(repo, ui, commit_checker, policies)
        if commit_checker.violations:
            ui.warn("pre-commit check failed")
            sys.exit(1)

    if args.commit_msg:
        ui.debug("commit-msg check, file %s" % args.commit_msg)
        msg_checker = checker(ui, None, policies)
        with open(args.commit_msg,"rb") as fh:
            msg = fh.read()
            msg_checker.check_commit_msg(msg)
            errs = msg_checker.done()
            if errs:
                ui.warn("commit-msg check failed")
                sys.exit(1)

    if args.all_files:
        # check all managed files in the current working tree
        ui.note("checking all managed files")
        g = Git(rootdir)
        files = g.ls_files().split("\n")
        files = [os.path.join(rootdir,f) for f in files]
        file_checker = checker(ui, None, policies)
        file_checker.check_files(files)
        file_checker.done()
        if file_checker.violations:
            ui.warn("--all_file check violations found: %d" % (file_checker.violations))
        
    if args.files:
        ui.note("checking files from command line " + ", ".join(args.files))
        file_checker = checker(ui, None, policies)
        file_checker.check_files(args.files)
        file_checker.done()
        if file_checker.violations:
            ui.warn("file check violations found: %d" % (file_checker.violations))

