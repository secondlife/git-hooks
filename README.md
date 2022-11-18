# Linden Lab Pre-commit Hooks

[![codecov](https://codecov.io/gh/secondlife/git-hooks/branch/main/graph/badge.svg?token=GR8A4SWE6C)](https://codecov.io/gh/secondlife/git-hooks)

A collection of [pre-commit][] scripts used for checking commits and files against [Linden coding standards][standards].

## Use

**Requirements:**

- [pre-commit][] - an open source program for managing git pre-commit behavior

You should have [pre-commit][] installed on your machine. Be sure you have your user-level Python Scripts directory on your `PATH`. ex. `C:\Users\USERNAME\Roaming\Python\Python39\Scripts` on Windows or `~/.local/bin` everywhere else. After doing so, you can run `pre-commit install` in any git project containing a `.pre-commit-config.yaml` file to install hooks and dependencies.

### Instructions for Second Life Viewer Development

Checkout the [viewer][] as normal. Then run:

```text
pre-commit install -f
pre-commit install -f -t commit-msg
```

If you need to manually run any hooks, you can do so:

Run a specific hook (by ID) over all files
```text
pre-commit run --all-files opensource-license
```

Run all hooks over all files
```text
pre-commit run --all-files
```

### Configuration File

To add these hooks to your own repository create a `.pre-commit-config.yaml` file in its root:

Example `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://bitbucket.org/lindenlab/git-hooks.git
    rev: v1.0.0-beta2
    hooks:
      - id: opensource-license
      - id: jira-issue
      - id: llsd
      - id: no-trigraphs
      - id: copyright
      - id: end-of-file
        files: \.(cpp|c|h|py|glsl|cmake|txt)$
        exclude: language.txt
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.1.0
    hooks:
      - id: check-xml
      - id: mixed-line-ending
```

### Provided hooks

- `copyright` - Check code for a copyright notice
- `end-of-file` - Check and fix any files that do not end in a newline.
- `indent-with-spaces` - Check if files that should be indented with spaces are (Python, etc.)
- `indent-with-tabs` - Check if files that should be indented with tabs are (Makefile, etc.)
- `jira-issue` - Check commit message for a valid Linden Jira ticket number
- `license` - Check code for a more generic license. Used on internal projects.
- `llsd` - Check that llsd files can be parsed
- `no-trigraphs` - Check C/C++ code for trigraphs
- `opensource-license` - Check code for an opensource license (MIT, LGPL, etc.)

### Use without pre-commit

It is also possible to use these scripts without [pre-commit][] by installing and running them yourself:

```text
# Clone this repository
git clone https://bitbucket.org/lindenlab/git-hooks.git
cd git-hooks
# Install the project using pip. This requires that $HOME/.local/bin is on your path
pip install .

# Run checks manually
check-linden-copyright [PATH TO FILE]
```

See `setup.cfg`'s `[options.entry_points]` for a full list of scripts.

### Development

To set up your development environment run

```text
pip install -e .[dev]
pre-commit install
```

[standards]: https://wiki.secondlife.com/wiki/Coding_standard
[pre-commit]: https://pre-commit.com/
[viewer]: https://bitbucket.org/lindenlab/viewer
