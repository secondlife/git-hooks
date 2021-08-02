import pytest
import tempfile

from git_hooks.llsd import main


VALID_LLSD = """<?xml version="1.0" encoding="UTF-8"?>
<llsd>
  <map>
    <key>foo</key>
    <string>bar</string>
  </map>
</llsd>
"""

INVALID_LLSD = """<?xml version="1.0" encoding="UTF-8"?>
<llsd>
  <key>foo</key>
</llsd>
"""

VALID_XML = """<?xml version="1.0" encoding="UTF-8"?>
<book>
  <chapter />
</book>
"""


@pytest.mark.parametrize(
    ("text", "expected_status"),
    (
        (VALID_LLSD, 0),
        (INVALID_LLSD, 1),
        (VALID_XML, 0),
        ("not llsd", 0),
    ),
)
def test_main(text, expected_status):
    with tempfile.NamedTemporaryFile(mode="w") as tmp:
        tmp.write(text)
        tmp.seek(0)
        status = main([tmp.name])
        assert status == expected_status
