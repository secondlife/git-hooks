import pytest

from git_hooks.end_of_file import main
from .support import temporary_file


@pytest.mark.parametrize(
    ("text", "expected_status"),
    (
        ("", 0),
        ("\nfile\n\n", 0),
        ("\nfoo", 1),
    ),
)
def test_main(text, expected_status):
    with temporary_file(mode="w") as tmp:
        tmp.write(text)
        tmp.close()
        status = main([tmp.name])
        assert status == expected_status
