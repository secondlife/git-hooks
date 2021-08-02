import pytest
import tempfile

from git_hooks.indent_with_tabs import main


@pytest.mark.parametrize(
    ("text", "expected_status"),
    (
        ("\nbuild:\n\t$GCC", 0),
        ("\nbuild:\n    $GCC", 1),
    ),
)
def test_main(text, expected_status):
    with tempfile.NamedTemporaryFile(mode="w") as tmp:
        tmp.write(text)
        tmp.seek(0)
        status = main([tmp.name])
        assert status == expected_status
