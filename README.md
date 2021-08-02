# Linden Lab Pre-commit Hooks

A collection of [pre-commit][] scripts used for checking commits and files against [Linden coding standards][standards].

## Use 

**Requirements:**

- [pre-commit][] - an open source program for managing git pre-commit behavior

You should have [pre-commit][] installed on your machine. After doing so, you can run `pre-commit install` in any git project containing a `.pre-commit-config.yaml` file to install hooks and dependencies.

Example `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://bitbucket.org/lindenlab/git-hooks
    rev: v1.0.0
    hooks:
      - id: opensource-license
      - id: jira-issue 
      - id: llsd
      - id: indent-with-spaces
      - id: indent-with-tabs
      - id: no-trigraphs
      - id: copyright
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.0.1
    hooks:
      - id: check-xml
      - id: end-of-file-fixer
      - id: mixed-line-ending
```

### Provided hooks

- `copyright` - Check code for a copyright notice
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

[standards]: https://wiki.secondlife.com/wiki/Coding_standard
[pre-commit]: https://pre-commit.com/

### Development

To set up your development environment run

```text
pip install -e .[dev]
```
