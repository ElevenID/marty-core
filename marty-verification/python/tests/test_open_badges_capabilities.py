"""The installed native capability contract must identify the OB3-only build."""

import marty_verification
import marty_verification_py
from marty_verification_py import _marty_verification


def test_open_badges_capability_is_ob3_only_on_native_and_public_surfaces():
    for module in (_marty_verification, marty_verification, marty_verification_py):
        assert module.OPEN_BADGES_SUPPORTED_VERSIONS == ("3.0",)
