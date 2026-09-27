"""Contract for the sanitized sccache diagnostic summary."""

import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from summarize_sccache_errors import main, summarize


class SummarizeSccacheErrorsTest(unittest.TestCase):
    def test_counts_status_context_without_printing_untrusted_text(self) -> None:
        lines = [
            "cache write error: HTTP 429 token=secret\n",
            "sccache response status code: 503 url=private\n",
            "cache write error: status=409\n",
            "cache write error: request id 429\n",
        ]
        total, write_errors, statuses = summarize(lines)
        self.assertEqual(total, 4)
        self.assertEqual(write_errors, 3)
        self.assertEqual(statuses, {"429": 1, "503": 1, "409": 1})

    def test_cli_reports_counts_without_raw_log_content(self) -> None:
        with TemporaryDirectory() as directory:
            log = Path(directory) / "sccache.log"
            log.write_text("cache write error: HTTP 429 token=secret\n", encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                main(log)
        self.assertIn("429: 1", output.getvalue())
        self.assertNotIn("secret", output.getvalue())


if __name__ == "__main__":
    unittest.main()
