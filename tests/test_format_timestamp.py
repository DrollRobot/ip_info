from datetime import datetime

import pytest

from ip_info._format_timestamp import _format_timestamp


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        # morning -> "AM" lowered to "am"
        (datetime(2024, 1, 5, 9, 30), "01-05-24 09:30am"),
        # afternoon -> "PM" lowered to "pm"
        (datetime(2024, 12, 31, 15, 45), "12-31-24 03:45pm"),
        # midnight edge case renders as 12:00am
        (datetime(2025, 6, 1, 0, 0), "06-01-25 12:00am"),
    ],
)
def test_format_timestamp(timestamp: datetime, expected: str) -> None:
    assert _format_timestamp(timestamp) == expected


def test_format_timestamp_rejects_non_datetime() -> None:
    with pytest.raises(TypeError, match=r"Expected a datetime object\."):
        _format_timestamp("2024-01-05")  # type: ignore[arg-type]
