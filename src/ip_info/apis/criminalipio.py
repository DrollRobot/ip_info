import ipaddress
import requests
import sqlite3
from datetime import datetime
from typing import Dict

from ip_info.config import LOCAL_TIMEZONE
from ip_info.db._add_to_db import _insert_ip_info, _insert_query_info
from ip_info.db._query_db import _check_rate_limits, _is_db_entry_recent


def criminalipio(
    *,
    api_name: str,
    api_display_name: str,
    ip_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    rate_limits: list[Dict],
    api_key: str,
    db_conn: sqlite3.Connection
) -> None:
    
    url = "https://api.criminalip.io/v1/asset/ip/report/summary"
    headers = {"x-api-key": api_key}

    # filter out ipv6 addresses. criminalip.io doesn't accept them?
    ip_addresses = [ip for ip in ip_addresses if isinstance(ip, ipaddress.IPv4Address)]

    for ip_address in ip_addresses:

        # skip if a recent entry exists
        if _is_db_entry_recent(api_name, ip_address, db_conn):
            continue

        # check rate limits
        if _check_rate_limits(api_name, rate_limits, db_conn):
            print("Rate limit reached. Skipping query.")
            continue

        params = {
            "ip": str(ip_address)
        }
        
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
        hostname = result.get("summary", {}).get("connection", {}).get("hostname", "")

        ### build flags string
        flags_strings = []
        # cdn
        if result.get("summary", {}).get("detection", {}).get("cdn_ip", {}):
            flags_strings.append("cdn")

        # # inbound
        # inbound = result.get("ip_scoring", {}).get("inbound", {})
        # if inbound != "safe":
        #     flags_strings.append(f"inbound:{inbound}")

        # hosting
        if result.get("summary", {}).get("detection", {}).get("hosting_ip", {}):
            flags_strings.append("hosting")

        # malicious
        if result.get("ip_scoring", {}).get("is_malicious", {}):
            flags_strings.append("malicious")

        # mobile
        if result.get("summary", {}).get("detection", {}).get("mobile_ip", {}):
            flags_strings.append("mobile")

        # # outbound
        # outbound = result.get("ip_scoring", {}).get("outbound", {})
        # if outbound != "safe":
        #     flags_strings.append(f"outbound:{outbound}")

        # proxy
        if result.get("summary", {}).get("detection", {}).get("proxy_ip", {}):
            flags_strings.append("proxy")

        # scanner
        if result.get("summary", {}).get("detection", {}).get("scanner_ip", {}):
            flags_strings.append("scanner")

        # tor
        if result.get("summary", {}).get("detection", {}).get("tor_ip", {}):
            flags_strings.append("tor")

        # vpn
        if result.get("summary", {}).get("detection", {}).get("vpn_ip", {}):
            flags_strings.append("vpn")

        if flags_strings:
            flags_string = ", ".join(flags_strings)
        else:
            flags_string = "-"

        # cc
        cc = result.get("summary", {}).get("connection", {}).get("country", "")
        if cc:
            cc = cc.upper()

        entry = {
            "timestamp": last_request_time,
            "ip_address": str(ip_address),
            "api_name": api_name,
            "api_display_name": api_display_name,
            "risk": "",
            "city": "",
            "state": "",
            "cc": "",
            "company": result.get("summary", {}).get("connection", {}).get("ip_address_owner", ""),
            "isp": "",
            "as_name": "",
            "hostname": hostname,
            "flags": flags_string,
            "raw_json": result
        }
        _insert_ip_info(entries=[entry], db_conn=db_conn)

