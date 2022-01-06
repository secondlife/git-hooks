# -*- coding: UTF-8 -*-
import pytest

from git_hooks.llsd import main
from .support import temporary_file


VALID_LLSD = u"""<?xml version="1.0" encoding="UTF-8"?>
<llsd>
  <map>
    <key>foo</key>
    <string>💻</string>
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
    with temporary_file(mode="wb") as tmp:
        tmp.write(text.encode("utf-8"))
        tmp.close()
        status = main([tmp.name])
        assert status == expected_status
