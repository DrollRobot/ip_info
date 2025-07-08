import ipaddress
import requests
import sqlite3
from datetime import datetime
from typing import Dict

from ip_info.config import LOCAL_TIMEZONE
from ip_info.db._add_to_db import _insert_ip_info, _insert_query_info
from ip_info.db._query_db import _check_rate_limits, _is_db_entry_recent


def ipgeolocationio(
    *,
    api_name: str,
    api_display_name: str,
    ip_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    rate_limits: list[Dict],
    api_key: str,
    db_conn: sqlite3.Connection
) -> None:
    
    url = "https://api.ipgeolocation.io/v2/ipgeo"

    for ip_address in ip_addresses:

        # skip if a recent entry exists
        if _is_db_entry_recent(api_name, ip_address, db_conn):
            continue

        # check rate limits
        if _check_rate_limits(api_name, rate_limits, db_conn):
            print("Rate limit reached. Skipping query.")
            continue

        # build request params
        params = {"apiKey": api_key, "ip": str(ip_address)}

        # make request
        try:
            print(f"Querying {api_display_name} for IP {ip_address}")
            response = requests.get(url, params=params)
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

        entry = {
            "timestamp": last_request_time,
            "ip_address": str(ip_address),
            "api_name": api_name,
            "api_display_name": api_display_name,
            "risk": "",
            "city": result.get("location", {}).get("city", ""),
            "state": result.get("location", {}).get("state_prov", ""),
            "cc": result.get("location", {}).get("country_code2", ""),
            "company": "",
            "isp": "",
            "as_name": "",
            "hostname": "",
            "flags": "",
            "raw_json": result
        }
        _insert_ip_info(entries=[entry], db_conn=db_conn)