"""Print counts from an sccache debug log without exposing its raw contents."""

from collections import Counter
from collections.abc import Iterable
from pathlib import Path
import re
import sys


HTTP_STATUS = re.compile(
    r"\b(?:HTTP(?:/\d(?:\.\d)?)?|status(?:\s+code)?)\D{0,24}(429|409|403|401|5\d\d)\b",
    re.IGNORECASE,
)


def summarize(lines: Iterable[str]) -> tuple[int, int, Counter[str]]:
    total = 0
    write_errors = 0
    statuses: Counter[str] = Counter()
    for line in lines:
        total += 1
        lower = line.lower()
        if "cache" in lower and "write" in lower and "error" in lower:
            write_errors += 1
        match = HTTP_STATUS.search(line)
        if match:
            statuses[match.group(1)] += 1
    return total, write_errors, statuses


def main(path: Path) -> None:
    if path.exists():
        with path.open(encoding="utf-8", errors="replace") as log:
            total, write_errors, statuses = summarize(log)
    else:
        total, write_errors, statuses = summarize(())
        print("sccache error log: absent")
    print(f"sccache diagnostic log lines: {total}")
    print(f"cache-write-error diagnostic lines: {write_errors}")
    print("Sanitized HTTP status mentions:")
    for status in ("429", "409", "403", "401"):
        print(f"{status}: {statuses[status]}")
    print(f"5xx: {sum(count for status, count in statuses.items() if status.startswith('5'))}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
