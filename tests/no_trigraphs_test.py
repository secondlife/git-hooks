import pytest
import tempfile

from git_hooks.no_trigraphs import main


@pytest.mark.parametrize(
    ("text", "expected_status"),
    (
        ("int main() ??< ??>", 1),
        ("int main() ??< ??<", 1),
        ("int main() { }", 0),
    ),
)
def test_main(text, expected_status):
    with tempfile.NamedTemporaryFile(mode="w") as tmp:
        tmp.write(text)
        tmp.seek(0)
        status = main([tmp.name])
        assert status == expected_status
