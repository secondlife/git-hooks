import pytest

from git_hooks.license import main
from .support import temporary_file

LICENSE = """/**
 * @file llfoo.cpp
 *
 * $LicenseInfo:firstyear=2001&license=internal$
 *
 * Copyright (c) 2001-2021, Linden Research, Inc.
 *
 * The following source code is PROPRIETARY AND CONFIDENTIAL. Use of
 * this source code is governed by the Linden Lab Source Code Disclosure
 * Agreement ("Agreement") previously entered between you and Linden
 * Lab. By accessing, using, copying, modifying or distributing this
 * software, you acknowledge that you have been informed of your
 * obligations under the Agreement and agree to abide by those obligations.
 *
 * ALL LINDEN LAB SOURCE CODE IS PROVIDED "AS IS." LINDEN LAB MAKES NO
 * WARRANTIES, EXPRESS, IMPLIED OR OTHERWISE, REGARDING ITS ACCURACY,
 * COMPLETENESS OR PERFORMANCE.
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
    with temporary_file(mode="w") as tmp:
        tmp.write(text)
        tmp.close()
        status = main([tmp.name])
        assert status == expected_status
