import requests
import sqlite3

from datetime import datetime, timedelta
from ip_info.config import LOCAL_TIMEZONE
from ip_info.db import is_ip_info_recent, insert_ip_info
from ip_info.next_query import get_next_query_dict, update_next_query_dict
from ip_info.format_timestamp import format_timestamp


def virustotalcom(ip_addresses, api_key, db_conn: sqlite3.Connection = None):
    """
    Query VirusTotal for IP addresses.

    Steps:
      1. For each IP, use is_ip_info_recent to check if a recent DB record exists.
      2. Enforce short-term rate limit: max 4 requests per minute.
      3. Enforce long-term rate limit: max 500 requests per day.
      4. For each IP, send GET request to VirusTotal IP endpoint.
      5. Parse last_analysis_stats to determine malicious and suspicious counts.
      6. Upsert records into database using insert_ip_info.

    Args:
        ip_addresses (list): A list of IPv4 or IPv6 address strings.
        api_key (str): Your VirusTotal API key.
    """
    api_name = "virustotal"
    api_display_name = "VirusTotal.com"
    base_url = "https://www.virustotal.com/api/v3/ip_addresses"
    last_request_time = None

    # long-term rate limit: check if daily limit reached
    next_query_dict = get_next_query_dict()
    next_allowed_time = next_query_dict.get(api_name)
    if next_allowed_time and datetime.now(LOCAL_TIMEZONE) < next_allowed_time:
        next_str = format_timestamp(next_allowed_time)
        print(f"Usage limit reached for {api_display_name}. Next query allowed after {next_str}.")
        return

    for ip_address in ip_addresses:
        # skip if a recent entry exists
        if is_ip_info_recent(api_name, ip_address, db_conn):
            continue

        url = f"{base_url}/{ip_address}"

        try:
            print(f"Querying {api_display_name} for {ip_address}")
            headers = {"x-apikey": api_key}
            response = requests.get(url, headers=headers)

            # handle rate-limit hit
            if response.status_code == 429:
                now = datetime.now(LOCAL_TIMEZONE)
                next_day = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
                update_next_query_dict(api_name, next_day)
                next_str = format_timestamp(next_day)
                print(f"Rate limit reached for {api_display_name}. Stopping further queries until {next_str}.")
                break

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
        insert_ip_info(entries=entry, db_conn=db_conn)