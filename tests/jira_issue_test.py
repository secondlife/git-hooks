import pytest

from git_hooks.jira_issue import main
from .support import temporary_file


@pytest.mark.parametrize(
    ("message", "expected_status"),
    (
        ("SL-1: Second Life should grow to dominate the world", 0),
        ("A message with merge in it", 0),
        ("A message without a valid project", 1),
        ("A message with an unrecognized PROJECT-123", 1),
    ),
)
def test_main(message, expected_status):
    with temporary_file(mode="w") as tmp:
        tmp.write(message)
        tmp.close()
        status = main([tmp.name])
        assert status == expected_status
