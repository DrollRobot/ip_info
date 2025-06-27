import ipaddress
import requests
import sqlite3

from ip_info.db import delete_from_db, is_ip_info_recent, store_in_db

def ipinfoio(ip_addresses, api_key, db_conn: sqlite3.Connection = None):

    api_name = "ipinfoio"
    api_display_name = "IPinfo.io"
    headers = {
        "Accept": "application/json"
    }

    for ip_address in ip_addresses:

        params = {"token": api_key}
        
        # skip if a recent entry exists
        if is_ip_info_recent(api_name, ip_address, db_conn):
            continue

        # choose the right endpoint based on IP version
        try:
            ip_obj = ipaddress.ip_address(ip_address)
        except ValueError:
            print(f"Invalid IP address: {ip_address}")
            continue
        if ip_obj.version == 6:
            base_url = "https://v6.ipinfo.io"  # IPv6‑specific endpoint :contentReference[oaicite:0]{index=0}
        else:
            base_url = "https://ipinfo.io"
        url = f"{base_url}/{ip_address}/json"

        try:
            print(f"Querying {api_display_name} for {ip_address}")
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            result = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error querying {api_display_name} for {ip_address}: {e}")
            continue

        # remove old records
        delete_from_db(api_name, ip_address, db_conn)

        # parse 'org' into ASN and company
        org = result.get("org", "")
        if org:
            parts = org.split(" ", 1)
            company = " ".join(parts[1:]) if len(parts) > 1 else ""
        else:
            company = ""

        store_in_db(
            ip_address=ip_address,
            api_name=api_name,
            api_display_name=api_display_name,
            risk="",
            city=result.get("city", ""),
            state=result.get("region", ""),
            cc=result.get("country", ""),
            company=company,
            isp="",
            as_name="",
            hostname=result.get("hostname", ""),
            flags="",
            raw_json=result,
            db_conn=db_conn,
        )