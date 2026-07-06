"""Client and parser for the IPAPI.com IP-info API."""

import ipaddress
import sqlite3
from datetime import datetime
from typing import Any

import requests

from ip_info.config import LOCAL_TIMEZONE, REQUEST_TIMEOUT
from ip_info.db._add_to_db import _insert_ip_info, _insert_query_info
from ip_info.db._query_db import _check_rate_limits, _is_db_entry_recent


def ipapicom(
    *,
    api_name: str,
    api_display_name: str,
    ip_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    rate_limits: list[dict[str, Any]],
    api_key: str,
    db_conn: sqlite3.Connection,
) -> None:
    """Query ipapi.com for each IP address and store the parsed results in the database."""
    base_url = "https://api.ipapi.com/api"

    # query each ip individually.
    for ip_address in ip_addresses:
        # skip query if a recent db entry exists.
        recent_entry = _is_db_entry_recent(api_name, ip_address, db_conn)
        if recent_entry:
            continue

        # check rate limits
        if _check_rate_limits(api_name, rate_limits, db_conn):
            print("Rate limit reached. Skipping query.")
            continue

        # build request params
        url = f"{base_url}/{ip_address}"
        params: dict[str, Any] = {
            "access_key": api_key,
            "output": "json",
            "hostname": 1,
            "language": "en",
        }
        headers: dict[str, str] = {}

        # make request
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
            print(f"Error querying {api_display_name} for IP {ip_address}: {e}")
            continue

        # save query time for ip database timestamp
        last_request_time = datetime.now(LOCAL_TIMEZONE)

        entry = {
            "timestamp": last_request_time,
            "ip_address": str(ip_address),
            "api_name": api_name,
            "api_display_name": api_display_name,
            "risk": "",
            "city": result.get("city", ""),
            "state": result.get("region_name", ""),
            "cc": result.get("country_code", ""),
            "company": "",
            "isp": "",
            "as_name": "",
            "hostname": result.get("hostname", ""),
            "flags": "",
            "raw_json": result,
        }
        _insert_ip_info(entries=[entry], db_conn=db_conn)
