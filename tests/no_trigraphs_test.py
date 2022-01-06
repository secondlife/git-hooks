import pytest

from git_hooks.no_trigraphs import main
from .support import temporary_file


@pytest.mark.parametrize(
    ("text", "expected_status"),
    (
        ("int main() ??< ??>", 1),
        ("int main() ??< ??<", 1),
        ("int main() { }", 0),
    ),
)
def test_main(text, expected_status):
    with temporary_file(mode="w") as tmp:
        tmp.write(text)
        tmp.close()
        status = main([tmp.name])
        assert status == expected_status
