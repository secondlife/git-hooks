import pytest
import tempfile

from git_hooks.copyright import main


COPYRIGHT = """/**
 * @file file.cpp
 *
 * $LicenseInfo:firstyear=2001&license=viewerlgpl$
 * Second Life Viewer Source Code
 * Copyright (C) 2021, Linden Research, Inc.
"""

NO_COPYRIGHT = """/**
 * @file file.cpp
 *
 * $LicenseInfo:firstyear=2001&license=viewerlgpl$
 * Second Life Viewer Source Code
"""


@pytest.mark.parametrize(
    ("text", "expected_status"),
    (
        (COPYRIGHT, 0),
        (NO_COPYRIGHT, 1),
    ),
)
def test_main(text, expected_status):
    with tempfile.NamedTemporaryFile(mode="w") as tmp:
        tmp.write(text)
        tmp.seek(0)
        status = main([tmp.name])
        assert status == expected_status
