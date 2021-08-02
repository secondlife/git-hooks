import pytest
import tempfile

from git_hooks.opensource_license import main

LICENSE = """/**
 * @file foo.cpp
 *
 * $LicenseInfo:firstyear=2001&license=viewerlgpl$
 * Second Life Viewer Source Code
 * Copyright (C) 2021, Linden Research, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License only.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Linden Research, Inc., 945 Battery Street, San Francisco, CA  94111  USA
 * $/LicenseInfo$
 */
"""

CODE = """
#include "linden_common.h"

LLFoo::LLFoo() : mBar(1)
{
}
"""


@pytest.mark.parametrize(
    ("text", "expected_status"),
    (
        (LICENSE + CODE, 0),
        (CODE, 1),
    ),
)
def test_main(text, expected_status):
    with tempfile.NamedTemporaryFile(mode="w") as tmp:
        tmp.write(text)
        tmp.seek(0)
        status = main([tmp.name])
        assert status == expected_status
