from datetime import datetime, timedelta
import requests
import sqlite3
import time

from ip_info.config import LOCAL_TIMEZONE
from ip_info.db import delete_from_db, is_ip_info_recent, store_in_db
from ip_info.next_query import get_next_query_dict, update_next_query_dict
from ip_info.format_timestamp import format_timestamp

RATE_LIMIT = 1 # not sure what their rate limit is

def ipapico(ip_addresses, db_conn: sqlite3.Connection = None):

    api_name = "ipapico"
    api_display_name = "IPAPI.co"
    base_url = "https://ipapi.co"
    last_request_time = None

    for ip_address in ip_addresses:

        # skip if a recent entry exists
        if is_ip_info_recent(api_name, ip_address, db_conn):
            continue

        url = f"{base_url}/{ip_address}/json/"

        # enforce rate limit: one request per second
        if last_request_time is not None:
            elapsed = (datetime.now(LOCAL_TIMEZONE) - last_request_time).total_seconds()
            if elapsed < RATE_LIMIT:
                time.sleep(RATE_LIMIT - elapsed)

        # check if query limit reached
        next_query_dict = get_next_query_dict()
        next_allowed = next_query_dict.get(api_name)
        if next_allowed and datetime.now(LOCAL_TIMEZONE) < next_allowed:
            print(
                f"Rate limit in effect for {api_display_name}. "
                f"Next query allowed after {format_timestamp(next_allowed)}."
            )
            return

        try:
            print(f"Querying {api_display_name} for {ip_address}")
            response = requests.get(url)

            # handle rate limit hit
            if response.status_code == 429:
                now = datetime.now(LOCAL_TIMEZONE)
                tomorrow = now + timedelta(days=1)
                next_dt = datetime(
                    tomorrow.year,
                    tomorrow.month,
                    tomorrow.day,
                    tzinfo=LOCAL_TIMEZONE
                )
                update_next_query_dict(api_name, next_dt)
                print(
                    f"Rate limit hit for {api_display_name}. "
                    f"Stopping queries until {format_timestamp(next_dt)}."
                )
                return

            response.raise_for_status()
            result = response.json()

        except requests.exceptions.RequestException as e:
            print(f"Error querying {api_display_name} for {ip_address}: {e}")
            continue

        # delete old record
        delete_from_db(api_name, ip_address, db_conn)

        store_in_db(
            ip_address=ip_address,
            api_name=api_name,
            api_display_name=api_display_name,
            risk="",
            city=result.get("city", ""),
            state=result.get("region", ""),
            cc=result.get("country", ""),
            company=result.get("org", ""),
            isp="",
            as_name=result.get("asn", ""),
            hostname="",
            flags="",
            raw_json=result,
            db_conn=db_conn,
        )
