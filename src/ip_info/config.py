import os
from zoneinfo import ZoneInfo
from typing import Any, Dict, Final


API_METADATA: Dict[str, Dict[str, Any]] = {
    "abstractapicom": {
        "api_display_name": "AbstractAPI.com",
        "requires_key": True,
        "allows_bulk": False,
        "rate_limits": [
            {
                "query_limit":   1,
                "timeframe": "second",
                "type":      "rolling",
                "status_code":  429,
                "error_text":   "Too many requests"
            },
            {
                "query_limit":   1000,
                "timeframe": "day",
                "type":      "absolute",
                "status_code":  422,
                "error_text":   "Quota reached"
            },
        ],
    },
    "abuseipdbcom": {
        "api_display_name": "AbuseIPDB.com",
        "requires_key": True,
        "allows_bulk": False,
        "rate_limits": [
            # no documented short term rate limit
            {
                "query_limit":   1000,
                "timeframe": "day",
                "type":      "absolute",
                "status_code":  429,
                "error_text": "Too many requests"
            },
        ],
    },
    "criminalipio": {
        "api_display_name": "CriminalIP.io",
        "requires_key": True,
        "allows_bulk": False,
        "rate_limits": [
            # short term rate limit: doesn't allow parallel queries
            {
                "query_limit":   50,
                "timeframe": "month",
                "type":     "absolute",
                "status_code":  429,
                "error_text": "Too many requests"
            },
        ],
    },
    "ip2locationio": {
        "api_display_name": "IP2Location.io",
        "requires_key": False,
        "allows_bulk": False,
        "rate_limits": [
            # no documented short term rate limit
            {
                "query_limit":   1000,
                "timeframe": "day",
                "type":     "absolute",
                "status_code":  10001,
                "error_text": "Invalid API key or insufficient query."
            },
        ],
    },
    "ipapico": {
        "api_display_name": "IPAPI.co",
        "requires_key": False,
        "allows_bulk": False,
        "rate_limits": [
            # no documented short term rate limit
            # adding per-minute limit due to excessive 429 failures
            {
                "query_limit":   2,
                "timeframe": "minute",
                "type":      "rolling",
            },
            {
                "query_limit":   1000,
                "timeframe": "day",
                "type":      "absolute",
                "status_code":  429,
            },
        ],
    },
    "ipapicom": {
        "api_display_name": "IPAPI.com",
        "requires_key": True,
        "allows_bulk": False,
        "rate_limits": [
            # no documented short term rate limit
            {
                "query_limit":   100,
                "timeframe": "month",
                "type":      "absolute",
                "status_code":  104,
                "error_text": "usage_limit_reached"
            },
        ],
    },
    "ipapiis": {
        "api_display_name": "IPAPI.is",
        "requires_key": True,
        "allows_bulk": True,
        "rate_limits": [
            # no documented short term rate limit
            {
                "query_limit":   1000,
                "timeframe": "day",
                "type":      "absolute",
                "status_code":  429,
            },
        ],
    },
    "ipapiorg": {
        "api_display_name": "IPAPI.org",
        "requires_key": True,
        "allows_bulk": True,
        "rate_limits": [
            # no documented short term rate limit
            {
                "query_limit":   1000,
                "timeframe": "day",
                "type":      "absolute",
            },
        ],
    },
    "ipdashapicom": {
        "api_display_name": "IP-API.com",
        "requires_key": False,
        "allows_bulk": True,
        "rate_limits": [
            {
                "query_limit":   15,
                "timeframe": "minute",
                "type":      "rolling",
                "status_code":  429,
            },            
            # no documented long term rate limit
        ],
    },
    "ipgeolocationio": {
        "api_display_name": "IPGeolocation.io",
        "requires_key": True,
        "allows_bulk": False,
        "rate_limits": [
            # no documented short term rate limit
            {
                "query_limit":   1000,
                "timeframe": "day",
                "type":      "absolute",
                "status_code":  429,
                "error_text": "Too many requests"
            },
        ],
    },
    "ipinfoio": {
        "api_display_name": "IPInfo.io",
        "requires_key": True,
        "allows_bulk": True,
        "rate_limits": [
            # no documented rate limits
            # adding this to wait for a minute if 429 returned
            {
                "query_limit":   1000,
                "timeframe": "minute",
                "type":      "rolling",
                "status_code":  429,
                "error_text": "Too many requests"
            },
        ],
    },
    "ipqueryio": {
        "api_display_name": "IPQuery.io",
        "requires_key": False,
        "allows_bulk": True,
        "rate_limits": [
            # no documented rate limits
        ],
    },
    "ipregistryco": {
        "api_display_name": "IPRegistry.co",
        "requires_key": True,
        "allows_bulk": True,
        "rate_limits": [
            # no documented rate limits, other than 100k per free account
            # adding this to wait for a minute if 429 returned
            {
                "query_limit":   1000,
                "timeframe": "minute",
                "type":      "rolling",
                "status_code":  429,
                "error_text": "TOO_MANY_REQUESTS"
            },
        ],
    },
    "virustotalcom": {
        "api_display_name": "VirusTotal.com",
        "requires_key": True,
        "allows_bulk": False,
        "rate_limits": [
            {
                "query_limit":   4,
                "timeframe": "minute",
                "type":      "rolling",
                "status_code":  429,
                "error_text": "QuotaExceededError"
            },
            {
                "query_limit":   500,
                "timeframe": "day",
                "type":      "absolute",
            },
        ],
    },
}

 
TIMEZONE_STRING = "America/New_York"
LOCAL_TIMEZONE = ZoneInfo(TIMEZONE_STRING)
MAX_AGE = 90

BASE_DIR: Final[str] = os.path.dirname(os.path.abspath(__file__))
DB_PATH : Final[str] = os.path.join(BASE_DIR, "ip_info.db")

IP_TABLE_NAME = 'ip_data'
IP_TABLE_COLUMNS = {
    "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
    "timestamp": "TIMESTAMP",
    "ip_address": "TEXT",
    "api_name": "TEXT",
    "api_display_name": "TEXT",
    "risk": "INTEGER",
    "city": "TEXT",
    "state": "TEXT",
    "cc": "TEXT",
    "company": "TEXT",
    "isp": "TEXT",
    "as_name": "TEXT",
    "hostname": "TEXT",
    "flags": "TEXT",
    "raw_json": "TEXT"
}
IP_INSERT_ORDER = [
    column
    for column in IP_TABLE_COLUMNS.keys()
    if column != "id"
]

QUERY_TABLE_NAME = "api_queries"
QUERY_TABLE_COLUMNS = {
    "id":        "INTEGER PRIMARY KEY AUTOINCREMENT",
    "api_name":  "TEXT",
    "timestamp": "TIMESTAMP",
    "status_code": "INTEGER",
    "error_text": "TEXT",
}
QUERY_INSERT_ORDER = [
    column
    for column in QUERY_TABLE_COLUMNS.keys()
    if column != "id"
]

TABLES = [
    {
        "name": IP_TABLE_NAME,
        "columns": IP_TABLE_COLUMNS,
        "indexes": [
            (f"idx_{IP_TABLE_NAME}", "(api_name, ip_address)")
        ],
    },
    {
        "name": QUERY_TABLE_NAME,
        "columns": QUERY_TABLE_COLUMNS,
        "indexes": [
            (f"idx_{QUERY_TABLE_NAME}", "(api_name, timestamp)")
        ],
    },
]