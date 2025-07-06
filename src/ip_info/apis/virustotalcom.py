from datetime import datetime
import requests
import sqlite3
from typing import Dict, List

from ip_info.config import LOCAL_TIMEZONE
from ip_info.db._add_to_db import _insert_ip_info, _insert_query_info
from ip_info.db._query_db import _check_rate_limits, _is_db_entry_recent


def virustotalcom(
    *,
    api_name: str,
    api_display_name: str,
    ip_addresses: List,
    rate_limits: List[Dict],
    api_key: str,
    db_conn: sqlite3.Connection
):
    
    base_url = "https://www.virustotal.com/api/v3/ip_addresses"

    for ip_address in ip_addresses:

        # skip if a recent entry exists
        if _is_db_entry_recent(api_name, ip_address, db_conn):
            continue

        # check rate limits
        if _check_rate_limits(api_name, rate_limits, db_conn):
            print("Rate limit reached. Skipping query.")
            continue

        # build request params
        url = f"{base_url}/{ip_address}"
        headers = {"x-apikey": api_key}

        try:
            print(f"Querying {api_display_name} for {ip_address}")
            response = requests.get(url, headers=headers)
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

        # parse analysis stats
        data = result.get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        flags_strings = []
        if malicious:
            flags_strings.append(f"malicious:{malicious}")
        if suspicious:
            flags_strings.append(f"suspicious:{suspicious}")
        if harmless:
            flags_strings.append(f"harmless:{harmless}")
        flags_string = ", ".join(flags_strings) if flags_strings else "-"

        entry = {
            "timestamp": last_request_time,
            "ip_address": ip_address,
            "api_name": api_name,
            "api_display_name": api_display_name,
            "risk": malicious,
            "city": "",
            "state": "",
            "cc": attrs.get("country", ""),
            "company": attrs.get("as_owner", ""),
            "isp": "",
            "as_name": attrs.get("as_owner", {}),
            "hostname": "",
            "flags": flags_string,
            "raw_json": result
        }
        _insert_ip_info(entries=[entry], db_conn=db_conn)