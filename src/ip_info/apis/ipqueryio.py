"""Client and parser for the ipquery.io IP-info API."""

import ipaddress
import sqlite3
from datetime import datetime
from typing import Any

import requests

from ip_info.config import LOCAL_TIMEZONE, REQUEST_TIMEOUT
from ip_info.db._add_to_db import _insert_ip_info, _insert_query_info
from ip_info.db._query_db import _is_db_entry_recent, _respect_rate_limit


def ipqueryio(
    *,
    api_name: str,
    api_display_name: str,
    ip_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    rate_limits: list[dict[str, Any]],
    api_key: str,
    db_conn: sqlite3.Connection,
) -> None:
    """Query ipquery.io in bulk and store the parsed results for each IP in the database."""
    url_base = "https://api.ipquery.io"
    max_chunk_size = 10000

    # filter out ips with recent entries in database
    ips_to_query = [ip for ip in ip_addresses if not _is_db_entry_recent(api_name, ip, db_conn)]
    if not ips_to_query:
        return

    for i in range(0, len(ips_to_query), max_chunk_size):
        # wait until the rate limit clears, or skip if the wait is too long
        if _respect_rate_limit(api_name, api_display_name, rate_limits, db_conn):
            continue

        # build request params
        chunk = [str(ip) for ip in ips_to_query[i : i + max_chunk_size]]
        url = f"{url_base}/{','.join(chunk)}"

        # make request
        try:
            if len(chunk) == 1:
                print(f"Querying {api_display_name} for {chunk[0]}")
            else:
                print(f"Querying {api_display_name} for {len(chunk)} IPs")
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            _insert_query_info(api_name, response, db_conn)

            # rate limit response
            if response.status_code != 200:
                print(
                    f"Received status code {response.status_code}, "
                    f"message {response.text}. Skipping query"
                )
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
            query_ip = result.get("ip")

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

            flags_string = ", ".join(flags_strings) if flags_strings else "-"

            entry = {
                "timestamp": last_request_time,
                "ip_address": query_ip,
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
                "raw_json": result,
            }
            _insert_ip_info(entries=[entry], db_conn=db_conn)
