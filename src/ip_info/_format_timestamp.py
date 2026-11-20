from datetime import datetime, tzinfo


def _format_timestamp(timestamp: datetime, tz: tzinfo | None = None) -> str:
    """Format a stored timestamp for display, in local time.

    The output format is "MM-dd-yy hh:mm(am/pm)", with am/pm in lowercase.

    Args:
        timestamp: A timezone-aware datetime. Stored timestamps are UTC.
        tz: The time zone to show it in. None, the default, means the
            computer's local time zone.

    Returns:
        The formatted string.

    Raises:
        TypeError: If *timestamp* is not a datetime.
        ValueError: If *timestamp* is naive: its time zone would be a guess.
    """
    if not isinstance(timestamp, datetime):
        raise TypeError("Expected a datetime object.")
    if timestamp.tzinfo is None:
        raise ValueError("Expected a timezone-aware datetime.")

    formatted = timestamp.astimezone(tz).strftime("%m-%d-%y %I:%M%p")
    return formatted.replace("AM", "am").replace("PM", "pm")
