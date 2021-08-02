import pytest
import tempfile

from git_hooks.jira_issue import main


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
    with tempfile.NamedTemporaryFile(mode="w") as tmp:
        tmp.write(message)
        tmp.seek(0)
        status = main([tmp.name])
        assert status == expected_status
