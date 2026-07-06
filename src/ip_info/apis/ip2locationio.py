"""Client and parser for the IP2Location.io IP-info API."""

import ipaddress
import sqlite3
from datetime import datetime
from typing import Any

import requests

from ip_info.config import LOCAL_TIMEZONE, REQUEST_TIMEOUT
from ip_info.db._add_to_db import _insert_ip_info, _insert_query_info
from ip_info.db._query_db import _is_db_entry_recent, _respect_rate_limit


def ip2locationio(
    *,
    api_name: str,
    api_display_name: str,
    ip_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    rate_limits: list[dict[str, Any]],
    api_key: str,
    db_conn: sqlite3.Connection,
) -> None:
    """Query IP2Location.io for each IP address and store the parsed results in the database."""
    url = "https://api.ip2location.io"
    headers: dict[str, str] = {}

    for ip_address in ip_addresses:
        # skip if a recent entry exists
        if _is_db_entry_recent(api_name, ip_address, db_conn):
            continue

        ### check rate limits
        # rate limit without key is 1k per day. With key, 50k per month.
        if api_key:
            rate_limits = [
                {
                    "query_limit": 50000,
                    "timeframe": "month",
                    "type": "absolute",
                    "status_code": 10001,
                    "error_text": "Invalid API key or insufficient query.",
                },
            ]
        if _respect_rate_limit(api_name, api_display_name, rate_limits, db_conn):
            continue

        params = {
            "ip": str(ip_address),
            "key": api_key,
            "format": "json",
        }

        try:
            print(f"Querying {api_display_name} for {ip_address}")
            response = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
            _insert_query_info(api_name, response, db_conn)

            # rate limit response
            if response.status_code != 200:
                print(
                    f"Received status code {response.status_code}, "
                    f"message {response.text}. Skipping query"
                )
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

        flags_string = ", ".join(flags_strings) if flags_strings else "-"

        entry = {
            "timestamp": last_request_time,
            "ip_address": str(ip_address),
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
            "raw_json": result,
        }
        _insert_ip_info(entries=[entry], db_conn=db_conn)
