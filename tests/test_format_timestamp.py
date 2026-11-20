from datetime import UTC, datetime, timedelta, timezone

import pytest

from ip_info._format_timestamp import _format_timestamp

pytestmark = pytest.mark.unit

EASTERN_STANDARD = timezone(timedelta(hours=-5))


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        # morning -> "AM" lowered to "am"
        (datetime(2024, 1, 5, 9, 30, tzinfo=UTC), "01-05-24 09:30am"),
        # afternoon -> "PM" lowered to "pm"
        (datetime(2024, 12, 31, 15, 45, tzinfo=UTC), "12-31-24 03:45pm"),
        # midnight edge case renders as 12:00am
        (datetime(2025, 6, 1, 0, 0, tzinfo=UTC), "06-01-25 12:00am"),
    ],
)
def test_format_timestamp(timestamp: datetime, expected: str) -> None:
    assert _format_timestamp(timestamp, UTC) == expected


def test_format_timestamp_converts_utc_to_the_display_zone() -> None:
    stored = datetime(2024, 1, 5, 14, 30, tzinfo=UTC)
    assert _format_timestamp(stored, EASTERN_STANDARD) == "01-05-24 09:30am"


def test_format_timestamp_defaults_to_local_time() -> None:
    stored = datetime(2024, 1, 5, 14, 30, tzinfo=UTC)
    expected = stored.astimezone().strftime("%m-%d-%y %I:%M%p").lower()
    assert _format_timestamp(stored) == expected


def test_format_timestamp_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        _format_timestamp(datetime(2024, 1, 5, 9, 30))


def test_format_timestamp_rejects_non_datetime() -> None:
    with pytest.raises(TypeError, match=r"Expected a datetime object\."):
        _format_timestamp("2024-01-05")  # type: ignore[arg-type]
