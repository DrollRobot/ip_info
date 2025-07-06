from datetime import datetime

def _format_timestamp(timestamp: datetime) -> str:
    """
    Formats a datetime object into a string.
    
    The output format is: "MM-dd-yy hh:mm(am/pm)"
    where AM/PM is converted to lowercase.
    
    Args:
        timestamp (datetime): The datetime object to format.
    
    Returns:
        str: The formatted datetime string.
    """
    if not isinstance(timestamp, datetime):
        raise TypeError("Expected a datetime object.")
    
    formatted = timestamp.strftime("%m-%d-%y %I:%M%p")
    formatted_lower = formatted.replace("AM", "am").replace("PM", "pm")
    return formatted_lower