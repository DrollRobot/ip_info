from datetime import datetime
import requests
import sqlite3
from typing import Dict, List

from ip_info.config import LOCAL_TIMEZONE
from ip_info.db._add_to_db import _insert_ip_info, _insert_query_info
from ip_info.db._query_db import _check_rate_limits, _is_db_entry_recent


def ip2locationio(
    *,
    api_name: str,
    api_display_name: str,
    ip_addresses: List,
    rate_limits: List[Dict],
    api_key: str,
    db_conn: sqlite3.Connection
) -> None:
    
    url = "https://api.ip2location.io"
    headers = {}

    for ip_address in ip_addresses:

        params = {
            "ip": ip_address,
            "key": api_key,
            "format": "json",
        }

        # skip if a recent entry exists
        if _is_db_entry_recent(api_name, ip_address, db_conn):
            continue

        ### check rate limits
        # rate limit without key is 1k per day. With key, 50k per month.
        if api_key:
            rate_limits = [
                {
                    "query_limit":   1000,
                    "timeframe": "day",
                    "type":     "absolute",
                    "status_code":  10001,
                    "error_text": "Invalid API key or insufficient query."
                },
            ]
        if _check_rate_limits(api_name, rate_limits, db_conn):
            print("Rate limit reached. Skipping query.")
            continue

        try:
            print(f"Querying {api_display_name} for {ip_address}")
            response = requests.get(url, headers=headers, params=params)
            _insert_query_info(api_name, response, db_conn)

            # rate limit response
            if response.status_code != 200:
                print(f"Received status code {response.status_code}, message {response.text}. Skipping query")
                continue

            response.raise_for_status()
            result = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error querying {api_display_name} for {ip_address}: {e}")
            continue

        # save query time for ip database timestamp
        last_request_time = datetime.now(LOCAL_TIMEZONE)

        ### build flags string
        flags_strings = []
        # proxy
        if result.get("is_proxy"):
            flags_strings.append("proxy")

        if flags_strings:
            flags_string = ", ".join(flags_strings)
        else:
            flags_string = "-"

        entry = {
            "timestamp": last_request_time,
            "ip_address": ip_address,
            "api_name": api_name,
            "api_display_name": api_display_name,
            "risk": "",
            "city": result.get("city_name", ""),
            "state": result.get("region_name", ""),
            "cc": result.get("country_code", ""),
            "company": "",
            "isp": "",
            "as_name": result.get("as", ""),
            "hostname": "",
            "flags": flags_string,
            "raw_json": result
        }
        _insert_ip_info(entries=[entry], db_conn=db_conn)