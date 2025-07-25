import ipaddress
import re
import requests
import sqlite3
from datetime import datetime
from typing import Dict

from ip_info.config import LOCAL_TIMEZONE
from ip_info.db._add_to_db import _insert_ip_info, _insert_query_info
from ip_info.db._query_db import _check_rate_limits, _is_db_entry_recent


def ipapiis(
    *,
    api_name: str,
    api_display_name: str,
    ip_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    rate_limits: list[Dict],
    api_key: str,
    db_conn: sqlite3.Connection
) -> None:
    
    url = "https://api.ipapi.is"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
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
        chunk = [str(ip) for ip in ips_to_query[i : i + max_chunk_size]]
        payload = {"ips": chunk, "key": api_key}

        # make request
        try:
            if len(chunk) == 1:
                print(f"Querying {api_display_name} for {chunk[0]}")
            else:
                print(f"Querying {api_display_name} for {len(chunk)} IPs")
            response = requests.post(url, headers=headers, json=payload)
            _insert_query_info(api_name, response, db_conn)

            # rate limit response
            if response.status_code != 200:
                print(f"Received status code {response.status_code}, message {response.text}. Skipping query")
                continue

            response.raise_for_status()
            results = (response.json())
        except requests.exceptions.RequestException as error:
            print(f"Error querying {api_display_name} for IPs {chunk}: {error}")
            continue

        # save query time for ip database timestamp
        last_request_time = datetime.now(LOCAL_TIMEZONE)

        # parse results
        for query_ip, result in results.items():

            # skip keys that aren't ip addresses
            if query_ip == "total_elapsed_ms":
                continue

            ### build flags string    
            flags_strings = []     
            # abuse
            if result.get("is_abuser", {}):
                flags_strings.append("abuse")

            # as_risk
            abuser_score_string = result.get("asn", {}).get("abuser_score", "")
            if (m := re.search(r"\(([^)]*?)\)", abuser_score_string)):
                as_risk_string = m.group(1)
                if as_risk_string not in {"Very Low", "Low"}:
                    flags_strings.append(f"as_risk:{as_risk_string}")

            # bogon
            if result.get("is_bogon", {}):
                flags_strings.append("bogon")

            # company_risk
            abuser_score_string = result.get("company", {}).get("abuser_score", "")
            if (m := re.search(r"\(([^)]*?)\)", abuser_score_string)):
                company_risk_string = m.group(1)
                if company_risk_string not in {"Very Low", "Low"}:
                    flags_strings.append(f"company_risk:{company_risk_string}")

            # datacenter
            if result.get("is_datacenter", {}):
                flags_strings.append("datacenter")

            # mobile
            if result.get("is_mobile", {}):
                flags_strings.append("mobile")

            # proxy
            if result.get("is_proxy", {}):
                flags_strings.append("proxy")

            # satellite
            if result.get("is_satellite", {}):
                flags_strings.append("satellite")

            # tor
            if result.get("is_tor", {}):
                flags_strings.append("tor")

            # vpn
            if result.get("is_vpn", {}):
                flags_strings.append("vpn")
                service = result.get("vpn", {}).get("service", "")
                if service:
                    flags_strings.append(service)

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
                "city": result.get("location", "").get("city", ""),
                "state": result.get("location", "").get("state", ""),
                "cc": result.get("location", "").get("country_code", ""),
                "company": result.get("company", "").get("name", ""),
                "isp": "",
                "as_name": result.get("asn", "").get("org", ""),
                "hostname": "",
                "flags": flags_string,
                "raw_json": result
            }
            _insert_ip_info(entries=[entry], db_conn=db_conn)