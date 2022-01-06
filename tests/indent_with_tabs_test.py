import pytest

from git_hooks.indent_with_tabs import main
from .support import temporary_file


@pytest.mark.parametrize(
    ("text", "expected_status"),
    (
        ("\nbuild:\n\t$GCC", 0),
        ("\nbuild:\n    $GCC", 1),
    ),
)
def test_main(text, expected_status):
    with temporary_file(mode="w") as tmp:
        tmp.write(text)
        tmp.close()
        status = main([tmp.name])
        assert status == expected_status
