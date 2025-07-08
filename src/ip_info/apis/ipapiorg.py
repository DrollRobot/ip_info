import ipaddress
import requests
import sqlite3
from datetime import datetime
from typing import Dict

from ip_info.config import LOCAL_TIMEZONE
from ip_info.db._add_to_db import _insert_ip_info, _insert_query_info
from ip_info.db._query_db import _check_rate_limits, _is_db_entry_recent


def ipapiorg(
    *,
    api_name: str,
    api_display_name: str,
    ip_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    rate_limits: list[Dict],
    api_key: str,
    db_conn: sqlite3.Connection
) -> None:
    
    url = "https://pro.ipapi.org/api_json/batch.php"
    max_chunk_size = 100

    # filter out ips with recent entries in database
    ips_to_query = [ip for ip in ip_addresses if not _is_db_entry_recent(api_name, ip, db_conn)]
    if not ips_to_query:
        return

    # split ips into chunks
    for i in range(0, len(ips_to_query), max_chunk_size):

        # check rate limits
        if _check_rate_limits(api_name, rate_limits, db_conn):
            print("Rate limit reached. Skipping query.")
            continue

        # build request params
        chunk = [str(ip) for ip in ips_to_query[i : i + max_chunk_size]]
        params = {
            "key": api_key,
            "ips": ",".join(chunk)
        }

        # make request
        try:
            if len(chunk) == 1:
                print(f"Querying {api_display_name} for {chunk[0]}")
            else:
                print(f"Querying {api_display_name} for {len(chunk)} IPs")
            response = requests.get(url, params=params)
            _insert_query_info(api_name, response, db_conn)

            # rate limit response
            if response.status_code != 200:
                print(f"Received status code {response.status_code}, message {response.text}. Skipping query")
                continue

            response.raise_for_status()
            results = response.json()
            # normalize result, if only one returned, cast to array
            if isinstance(results, dict):
                results = [results]
        except requests.exceptions.RequestException as e:
            print(f"Error querying {api_display_name}: {e}")
            continue

        # save query time for ip database timestamp
        last_request_time = datetime.now(LOCAL_TIMEZONE)

        for result in results:

            if result.get("status") == "fail":
                print(f"Query failed: {result.get('message')}")
                continue

            query_ip = result.get("query")
            if not query_ip:
                continue

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
                "ip_address": query_ip,
                "api_name": api_name,
                "api_display_name": api_display_name,
                "risk": "",
                "city": result.get("city", ""),
                "state": result.get("regionName", "") or result.get("region", ""),
                "cc": result.get("countryCode", ""),
                "company": "",
                "isp": result.get("isp", ""),
                "as_name": result.get("as", ""),
                "hostname": "",
                "flags": flags_string,
                "raw_json": result
            }
            _insert_ip_info(entries=[entry], db_conn=db_conn)