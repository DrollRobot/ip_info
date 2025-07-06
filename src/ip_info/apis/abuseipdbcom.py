from datetime import datetime
import requests
import sqlite3
from typing import Dict, List

from ip_info.config import LOCAL_TIMEZONE
from ip_info.db._add_to_db import _insert_ip_info, _insert_query_info
from ip_info.db._query_db import _check_rate_limits, _is_db_entry_recent


def abuseipdbcom(
    *,
    api_name: str,
    api_display_name: str,
    ip_addresses: List,
    rate_limits: List[Dict],
    api_key: str,
    db_conn: sqlite3.Connection
) -> None:
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": api_key}

    for ip_address in ip_addresses:

        params = {"ipAddress": ip_address, "maxAgeInDays": "365"}

        # skip if a recent entry exists
        if _is_db_entry_recent(api_name, ip_address, db_conn):
            continue

        # check rate limits
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

        # hostname
        hostnames = result.get("data", {}).get("hostnames", "")
        if hostnames:
            hostname = hostnames[0]
        else:
            hostname = None

        ### build flags string
        flags_strings = []
        # reports
        reports = result.get("data", {}).get("totalReports", 0)
        if reports != 0:
            flags_strings.append(f"reports:{reports}")
        # risk
        risk = result.get("data", {}).get("abuseConfidenceScore", 0)
        if risk != 0:
            flags_strings.append(f"risk:{risk}")
        # tor
        if result.get("data", {}).get("isTor", {}):
            flags_strings.append("tor")
        # join strings
        if flags_strings:
            flags_string = ", ".join(flags_strings)
        else:
            flags_string = "-"

        entry = {
            "timestamp": last_request_time,
            "ip_address": ip_address,
            "api_name": api_name,
            "api_display_name": api_display_name,
            "risk": risk,
            "city": "",
            "state": "",
            "cc": result.get("data", {}).get("countryCode", ""),
            "company": "",
            "isp": result.get("data", {}).get("isp", ""),
            "as_name": "",
            "hostname": hostname,
            "flags": flags_string,
            "raw_json": result
        }
        _insert_ip_info(entries=[entry], db_conn=db_conn)
