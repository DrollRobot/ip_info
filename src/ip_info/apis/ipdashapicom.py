from datetime import datetime
import requests
import sqlite3
from typing import Dict, List

from ip_info.config import LOCAL_TIMEZONE
from ip_info.db._add_to_db import _insert_ip_info, _insert_query_info
from ip_info.db._query_db import _check_rate_limits, _is_db_entry_recent


def ipdashapicom(
    *,
    api_name: str,
    api_display_name: str,
    ip_addresses: List,
    rate_limits: List[Dict],
    api_key: str,
    db_conn: sqlite3.Connection
):
    
    url = "http://ip-api.com/batch"
    params = {
        "fields": "66842623"
    }
    max_chunk_size = 100

    # filter out ips with recent entries in database
    ips_to_query = [ip for ip in ip_addresses if not _is_db_entry_recent(api_name, ip, db_conn)]
    if not ips_to_query:
        return

    # split ips into chunks for bulk query
    for i in range(0, len(ips_to_query), max_chunk_size):

        # check rate limits
        if _check_rate_limits(api_name, rate_limits, db_conn):
            print("Rate limit reached. Skipping query.")
            continue

        # build request params
        chunk = ips_to_query[i : i + max_chunk_size]

        # make request
        try:
            if len(chunk) == 1:
                print(f"Querying {api_display_name} for {chunk[0]}.")
            else:
                print(f"Querying {api_display_name} for {len(chunk)} IPs.")
            response = requests.post(url, params=params, json=chunk)
            _insert_query_info(api_name, response, db_conn)

            # rate limit response
            if response.status_code != 200:
                print(f"Received status code {response.status_code}, message {response.text}. Skipping query")
                continue

            response.raise_for_status()
            results = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error querying {api_display_name}: {e}")
            return None
        
        # process each result in the batch
        for result in results:
            ip_address = result.get("query")
            if not ip_address:
                continue

            # save query time for ip database timestamp
            last_request_time = datetime.now(LOCAL_TIMEZONE)

            ### build flags string
            flags_strings = []
            # hosting
            if result.get("hosting", {}):
                flags_strings.append("hosting")

            # mobile
            if result.get("mobile", {}):
                flags_strings.append("mobile")

            # proxy
            if result.get("proxy", {}):
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
                "city": result.get("city", ""),
                "state": result.get("regionName", ""),
                "cc": result.get("countryCode", ""),
                "company": result.get("org", ""),
                "isp": result.get("isp", ""),
                "as_name": result.get("asname", ""),
                "hostname": "",
                "flags": flags_string,
                "raw_json": result
            }
            _insert_ip_info(entries=[entry], db_conn=db_conn)