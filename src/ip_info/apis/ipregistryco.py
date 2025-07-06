from datetime import datetime
import requests
import sqlite3
from typing import Dict, List

from ip_info.config import LOCAL_TIMEZONE
from ip_info.db._add_to_db import _insert_ip_info, _insert_query_info
from ip_info.db._query_db import _check_rate_limits, _is_db_entry_recent


def ipregistryco(
    *,
    api_name: str,
    api_display_name: str,
    ip_addresses: List,
    rate_limits: List[Dict],
    api_key: str,
    db_conn: sqlite3.Connection
):
    
    max_chunk_size = 1024
    params = {
        "key": api_key
    }

    # filter out ips that already have a recent db entry
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
        url = f"https://api.ipregistry.co/{ip_string}"

        try:
            if len(chunk) == 1:
                print(f"Querying {api_display_name} for {chunk[0]}.")
            else:
                print(f"Querying {api_display_name} for {len(chunk)} IPs.")
            response = requests.get(url, params=params)
            _insert_query_info(api_name, response, db_conn)

            # rate limit response
            if response.status_code != 200:
                print(f"Received status code {response.status_code}, message {response.text}. Skipping query")
                continue

            response.raise_for_status()
            results = response.json()
        except requests.exceptions.RequestException as error:
            print(f"Error querying {api_display_name}: {error}")
            return

        ### normalize to list
        if isinstance(results, dict):
            # if results has a sub-element called results, select it
            if "results" in results:      
                results = results["results"]
            # otherwise, wrap single dict in list so for loop will work correctly
            else:
                results = [results]
        else:
            raise TypeError("Response format invalid")

        # save query time for ip database timestamp
        last_request_time = datetime.now(LOCAL_TIMEZONE)

        for result in results:

            ip_address = result.get("ip")
            if not ip_address:
                continue

            ### build flags string
            flags_strings = []
            # abuse
            if result.get("security", {}).get("is_abuser", {}):
                flags_strings.append("abuse")
            # anonymous
            if result.get("security", {}).get("is_anonymous", {}):
                flags_strings.append("anonymous")
            # attacker
            if result.get("security", {}).get("is_attacker", {}):
                flags_strings.append("anoattackernymous")
            # bogon
            if result.get("security", {}).get("is_bogon", {}):
                flags_strings.append("bogon")
            # cloud
            if result.get("security", {}).get("is_cloud_provider", {}):
                flags_strings.append("cloud")
            # proxy
            if result.get("security", {}).get("is_proxy", {}):
                flags_strings.append("proxy")
            # relay
            if result.get("security", {}).get("is_relay", {}):
                flags_strings.append("relay")
            # threat
            if result.get("security", {}).get("is_threat", {}):
                flags_strings.append("threat")
            # tor
            tor = result.get("security", {}).get("is_tor", {})
            tor_exit = result.get("security", {}).get("is_tor_exit", {})
            if tor or tor_exit:
                flags_strings.append("tor")
            # vpn
            if result.get("security", {}).get("is_vpn", {}):
                flags_strings.append("vpn")

            if flags_strings:
                unique_flags_strings = list(dict.fromkeys(flags_strings))
                flags_string = ", ".join(unique_flags_strings)
            else:
                flags_string = "-"

            entry = {
                "timestamp": last_request_time,
                "ip_address": ip_address,
                "api_name": api_name,
                "api_display_name": api_display_name,
                "risk": "",
                "city": result.get("location", {}).get("city", ""),
                "state": result.get("location", {}).get("region", {}).get("name", ""),
                "cc": result.get("location", {}).get("country", {}).get("code", ""),
                "company": result.get("connection", {}).get("organization", ""),
                "isp": "",
                "as_name": result.get("connection", {}).get("asn", ""),
                "hostname": result.get("connection", {}).get("domain", ""),
                "flags": flags_string,
                "raw_json": result
            }
            _insert_ip_info(entries=[entry], db_conn=db_conn)