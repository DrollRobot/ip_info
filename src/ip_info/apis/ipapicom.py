from datetime import datetime
import requests
import sqlite3

from ip_info.config import LOCAL_TIMEZONE
from ip_info.db import delete_from_db, is_ip_info_recent, store_in_db
from ip_info.next_query import get_next_query_dict, update_next_query_dict
from ip_info.format_timestamp import format_timestamp

def ipapicom(ip_addresses, api_key, db_conn: sqlite3.Connection = None, fields=None, api_output_type="json"):

    api_name = "ipapicom"
    api_display_name = "IPAPI.com"
    base_url = "https://api.ipapi.com/api"
    dt_now = datetime.now(LOCAL_TIMEZONE)

    # query each ip individually.
    for ip_address in ip_addresses:

        # skip query if a recent db entry exists.
        recent_entry = is_ip_info_recent(api_name, ip_address, db_conn)
        if recent_entry:
            continue

        # check if rate limit reached
        next_query_dict = get_next_query_dict()
        next_allowed_time = next_query_dict.get(api_name)
        if next_allowed_time and datetime.now(LOCAL_TIMEZONE) < next_allowed_time:
            next_allowed_string = format_timestamp(next_allowed_time)
            print(
                f"Usage limit reached for {api_display_name}. Next query allowed after {next_allowed_string}."
            )
            return

        # build the url and parameters.
        url = f"{base_url}/{ip_address}"
        params = {
            "access_key": api_key,
            "output": api_output_type,
            "hostname": 1,
            "language": "en",
        }
        if fields:
            params["fields"] = fields

        headers = {}

        try:
            print(f"Querying {api_display_name} for {ip_address}")
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            result = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error querying {api_display_name} for IP {ip_address}: {e}")
            continue

        # if the response indicates usage limit reached, update the csv and stop processing
        if "error" in result and result["error"].get("code") == 104:
            # calculate the beginning of the next month.
            if dt_now.month == 12:
                next_query_dt = datetime(dt_now.year + 1, 1, 1)
            else:
                next_query_dt = datetime(dt_now.year, dt_now.month + 1, 1)
            update_next_query_dict(api_name, next_query_dt)
            next_query_string = format_timestamp(next_query_dt)
            print(
                f"Usage limit reached for {api_display_name}. Stopping further queries until {next_query_string}."
            )
            return

        delete_from_db(api_name, ip_address, db_conn)

        store_in_db(
            ip_address=ip_address,
            api_name=api_name,
            api_display_name=api_display_name,
            risk="",
            city=result.get("city", ""),
            state=result.get("region_name", ""),
            cc=result.get("country_code", ""),
            company="",
            isp="",
            as_name="",
            hostname=result.get("hostname", ""),
            flags="",
            raw_json=result,
            db_conn=db_conn,
        )