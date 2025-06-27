import requests
import sqlite3

from ip_info.db import delete_from_db, is_ip_info_recent, store_in_db

def ip2locationio(ip_addresses, api_key, db_conn: sqlite3.Connection = None):
    api_name = "ip2locationio"
    api_display_name = "IP2Location.io"
    url = "https://api.ip2location.io"
    headers = {}

    for ip_address in ip_addresses:
        flags_strings = []

        # skip if a recent entry exists
        if is_ip_info_recent(api_name, ip_address, db_conn):
            continue

        params = {
            "ip": ip_address,
            "key": api_key,
            "format": "json",
        }

        try:
            print(f"Querying {api_display_name} for {ip_address}")
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            result = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error querying {api_display_name} for {ip_address}: {e}")
            continue

        # delete old record
        delete_from_db(api_name, ip_address, db_conn)

        # build flags string
        # proxy
        if result.get("is_proxy"):
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
            city=result.get("city_name", ""),
            state=result.get("region_name", ""),
            cc=result.get("country_code", ""),
            company="",
            isp="",
            as_name=result.get("as", ""),
            hostname="",
            flags=flags_string,
            raw_json=result,
            db_conn=db_conn,
        )