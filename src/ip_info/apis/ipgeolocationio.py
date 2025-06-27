import requests
import sqlite3

from ip_info.db import delete_from_db, is_ip_info_recent, store_in_db

def ipgeolocationio(ip_addresses, api_key, db_conn: sqlite3.Connection = None):

    api_name = "ipgeolocationio"
    api_display_name = "IPGeolocation.io"
    url = "https://api.ipgeolocation.io/ipgeo"

    for ip_address in ip_addresses:

        # skip if a recent entry exists
        if is_ip_info_recent(api_name, ip_address, db_conn):
            continue

        params = {"apiKey": api_key, "ip": ip_address}

        try:
            print(f"Querying {api_display_name} for IP {ip_address}")
            response = requests.get(url, params=params)
            response.raise_for_status()
            result = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error querying {api_display_name} for {ip_address}: {e}")
            continue

        # remove any old record
        delete_from_db(api_name, ip_address, db_conn)

        store_in_db(
            ip_address=ip_address,
            api_name=api_name,
            api_display_name=api_display_name,
            risk="",
            city=result.get("city", ""),
            state=result.get("state_prov", ""),
            cc=result.get("country_code2", ""),
            company=result.get("organization", "") or result.get("isp", ""),
            isp=result.get("isp", ""),
            as_name="",
            hostname="",
            flags="",
            raw_json=result,
            db_conn=db_conn,
        )