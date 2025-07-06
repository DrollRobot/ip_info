from datetime import datetime
import requests
import sqlite3
from typing import Dict, List

from ip_info.config import LOCAL_TIMEZONE
from ip_info.db._add_to_db import _insert_ip_info, _insert_query_info
from ip_info.db._query_db import _check_rate_limits, _is_db_entry_recent


def ipqueryio(
    *,
    api_name: str,
    api_display_name: str,
    ip_addresses: List,
    rate_limits: List[Dict],
    api_key: str,
    db_conn: sqlite3.Connection
):
    
    url_base = "https://api.ipquery.io"
    max_chunk_size = 10000

    # filter out ips with recent entries in database
    ips_to_query = [ip for ip in ip_addresses if not _is_db_entry_recent(api_name, ip, db_conn)]
    if not ips_to_query:
        return

    for i in range(0, len(ips_to_query), max_chunk_size):

        # check rate limits
        if _check_rate_limits(api_name, rate_limits, db_conn):
            print("Rate limit reached. Skipping query.")
            continue

        # build request params
        chunk = ips_to_query[i : i + max_chunk_size]
        ip_string = ",".join(chunk)
        url = f"{url_base}/{ip_string}"

        # make request
        try:
            if len(chunk) == 1:
                print(f"Querying {api_display_name} for {chunk[0]}.")
            else:
                print(f"Querying {api_display_name} for {len(chunk)} IPs.")
            response = requests.get(url)
            _insert_query_info(api_name, response, db_conn)

            # rate limit response
            if response.status_code != 200:
                print(f"Received status code {response.status_code}, message {response.text}. Skipping query")
                continue

            response.raise_for_status()
            results = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error querying {api_display_name}: {e}")
            return

        # normalize to list
        results = results if isinstance(results, list) else [results]

        # save query time for ip database timestamp
        last_request_time = datetime.now(LOCAL_TIMEZONE)

        for result in results:

            ip_address = result.get("ip")

            ### build flags string
            flags_strings = []
            # datacenter
            if result.get("risk", {}).get("is_datacenter", {}):
                flags_strings.append("datacenter")

            # mobile
            if result.get("risk", {}).get("is_mobile", {}):
                flags_strings.append("mobile")

            # proxy
            if result.get("risk", {}).get("is_proxy", {}):
                flags_strings.append("proxy")

            # risk
            risk = result.get("risk", {}).get("risk_score", {})
            if risk != 0:
                flags_strings.append(f"risk:{risk}")

            # tor
            if result.get("risk", {}).get("is_tor", {}):
                flags_strings.append("tor")

            # vpn
            if result.get("risk", {}).get("is_vpn", {}):
                flags_strings.append("vpn")

            if flags_strings:
                flags_string = ", ".join(flags_strings)
            else:
                flags_string = "-"

            entry = {
                "timestamp": last_request_time,
                "ip_address": ip_address,
                "api_name": api_name,
                "api_display_name": api_display_name,
                "risk": result.get("risk", {}).get("risk_score", 0),
                "city": result.get("location", {}).get("city", ""),
                "state": result.get("location", {}).get("state", ""),
                "cc": result.get("location", {}).get("country_code", ""),
                "company": result.get("isp", {}).get("org", ""),
                "isp": result.get("isp", {}).get("isp", ""),
                "as_name": result.get("isp", {}).get("asn", ""),
                "hostname": "",
                "flags": flags_string,
                "raw_json": result
            }
            _insert_ip_info(entries=[entry], db_conn=db_conn)