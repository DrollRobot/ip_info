"""Client and parser for the AbstractAPI IP-info API."""

import ipaddress
import sqlite3
from datetime import datetime
from typing import Any

import requests

from ip_info.config import LOCAL_TIMEZONE, REQUEST_TIMEOUT
from ip_info.db._add_to_db import _insert_ip_info, _insert_query_info
from ip_info.db._query_db import _check_rate_limits, _is_db_entry_recent


def abstractapicom(
    *,
    api_name: str,
    api_display_name: str,
    ip_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    rate_limits: list[dict[str, Any]],
    api_key: str,
    db_conn: sqlite3.Connection,
) -> None:
    """Query AbstractAPI for each IP address and store the parsed results in the database."""
    url = "https://ip-intelligence.abstractapi.com/v1/"

    for ip_address in ip_addresses:
        # skip if a recent entry exists
        if _is_db_entry_recent(api_name, ip_address, db_conn):
            continue

        # check rate limits
        if _check_rate_limits(api_name, rate_limits, db_conn):
            print("Rate limit reached. Skipping query.")
            continue

        params = {"api_key": api_key, "ip_address": str(ip_address)}

        try:
            print(f"Querying {api_display_name} for {ip_address}")
            response = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
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
        # abuse
        if result.get("security", {}).get("is_abuse"):
            flags_strings.append("abuse")

        # hosting
        if result.get("security", {}).get("is_hosting"):
            flags_strings.append("hosting")

        # mobile
        if result.get("security", {}).get("is_mobile"):
            flags_strings.append("mobile")

        # vpn
        if result.get("security", {}).get("is_vpn"):
            flags_strings.append("vpn")

        # proxy
        if result.get("security", {}).get("is_proxy"):
            flags_strings.append("proxy")

        # relay
        if result.get("security", {}).get("is_relay"):
            flags_strings.append("relay")

        # tor
        if result.get("security", {}).get("is_tor"):
            flags_strings.append("tor")

        flags_string = ", ".join(flags_strings) if flags_strings else "-"

        entry = {
            "timestamp": last_request_time,
            "ip_address": str(ip_address),
            "api_name": api_name,
            "api_display_name": api_display_name,
            "risk": "",
            "city": result.get("location", {}).get("city", ""),
            "state": result.get("location", {}).get("region", ""),
            "cc": result.get("location", {}).get("country_code", ""),
            "company": result.get("company", {}).get("name", ""),
            "isp": "",
            "as_name": result.get("asn", {}).get("name", ""),
            "hostname": "",
            "flags": flags_string,
            "raw_json": result,
        }
        _insert_ip_info(entries=[entry], db_conn=db_conn)
