import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import check_zkp_android_crosslink as crosslink


class AndroidCrosslinkAdmissionTests(unittest.TestCase):
    def refuse(self, environment, message, ndk="absent-ndk"):
        with mock.patch.object(sys, "platform", "linux"), \
                mock.patch.object(sys, "argv", ["check", "--ndk-root", str(ndk)]), \
                mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(crosslink.subprocess, "run") as run:
            with self.assertRaisesRegex(SystemExit, message):
                crosslink.main()
            run.assert_not_called()

    def test_mock_selection_is_refused_before_any_tools_or_artifacts(self):
        for environment in (
            {"USE_ZK_MOCK": "1"}, {"CARGO_FEATURE_ZK_MOCK": ""},
            {"RUSTFLAGS": "--cfg zk_mock"},
            {"CARGO_ENCODED_RUSTFLAGS": "--cfg\x1fzk_mock"},
        ):
            with self.subTest(environment=environment):
                self.refuse(environment, "may not use the ZK mock")

    def test_host_zstd_selection_including_empty_value_is_refused(self):
        for value in ("", "0", "1"):
            with self.subTest(value=value):
                self.refuse({"ZSTD_SYS_USE_PKG_CONFIG": value}, "may not adopt host zstd")

    def test_wrong_ambiguous_or_nonexact_ndk_revision_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            ndk = Path(directory)
            for properties in (
                "Pkg.Revision = 27.2.12479018\n",
                f"Pkg.RevisionExtra = {crosslink.NDK_VERSION}\n",
                f"Pkg.Revision = {crosslink.NDK_VERSION}\n" * 2,
            ):
                with self.subTest(properties=properties):
                    (ndk / "source.properties").write_text(properties, encoding="utf-8")
                    self.refuse({}, "requires the pinned NDK revision", ndk)


if __name__ == "__main__":
    unittest.main()
