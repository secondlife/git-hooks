import pytest

from git_hooks.indent_with_spaces import main
from .support import temporary_file


@pytest.mark.parametrize(
    ("text", "expected_status"),
    (
        ("def foo():\n   return 1", 0),
        ("def foo():\n\treturn 1", 1),
    ),
)
def test_main(text, expected_status):
    with temporary_file(mode="w") as tmp:
        tmp.write(text)
        tmp.close()
        status = main([tmp.name])
        assert status == expected_status
