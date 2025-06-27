from datetime import datetime, timedelta
import requests
import sqlite3

from ip_info.config import LOCAL_TIMEZONE
from ip_info.db import delete_from_db, is_ip_info_recent, store_in_db
from ip_info.next_query import get_next_query_dict, update_next_query_dict
from ip_info.format_timestamp import format_timestamp

def ipdashapicom(ip_addresses, db_conn: sqlite3.Connection = None):

    api_name = "ipdashapicom"
    api_display_name = "IP-API.com"
    max_chunk_size = 100
    url = "http://ip-api.com/batch"
    params = {"fields": "66842623"}

    # filter out ips that already have a recent db entry
    ips_to_query = [ip for ip in ip_addresses if not is_ip_info_recent(api_name, ip, db_conn)]
    if not ips_to_query:
        return

    # split ips into chunks
    for i in range(0, len(ips_to_query), max_chunk_size):

        chunk = ips_to_query[i : i + max_chunk_size]

        # check if rate limit reached
        next_query_dict = get_next_query_dict()
        next_allowed_time = next_query_dict.get(api_name)
        if next_allowed_time and datetime.now(LOCAL_TIMEZONE) < next_allowed_time:
            next_allowed_string = format_timestamp(next_allowed_time)
            print(
                f"Usage limit reached for {api_display_name}. Next query allowed after {next_allowed_string}."
            )
            return

        # run query
        try:
            if len(chunk) == 1:
                print(f"Querying {api_display_name} for {chunk[0]}.")
            else:
                print(f"Querying {api_display_name} for {len(chunk)} IPs.")
            response = requests.post(url, params=params, json=chunk)

            # handle rate-limit headers X‑Rl and X‑Ttl
            if "X-Rl" in response.headers and "X-Ttl" in response.headers:
                remaining = int(response.headers["X-Rl"])
                ttl = int(response.headers["X-Ttl"])
                if remaining == 0:
                    next_query_dt = datetime.now(LOCAL_TIMEZONE) + timedelta(seconds=ttl)
                    update_next_query_dict(api_name, next_query_dt)
                    next_query_string = format_timestamp(next_query_dt)
                    print(
                        f"Usage limit reached for {api_display_name}. "
                        f"Stopping further queries until {next_query_string}."
                    )
                    return

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

            flags_strings = []

            delete_from_db(api_name, ip_address, db_conn)

            ### build flags string
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

            store_in_db(
                ip_address=ip_address,
                api_name=api_name,
                api_display_name=api_display_name,
                risk="",
                city=result.get("city", ""),
                state=result.get("regionName", ""),
                cc=result.get("countryCode", ""),
                company=result.get("org", ""),
                isp=result.get("isp", ""),
                as_name=result.get("asname", ""),
                hostname="",
                flags=flags_string,
                raw_json=result,
                db_conn=db_conn,
            )