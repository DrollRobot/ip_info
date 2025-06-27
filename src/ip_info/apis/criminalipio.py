import requests
import sqlite3

from ip_info.db import delete_from_db, is_ip_info_recent, store_in_db

def criminalipio(ip_addresses, api_key, db_conn: sqlite3.Connection = None):
    api_name = "criminalipio"
    api_display_name = "CriminalIP.io"
    url = "https://api.criminalip.io/v1/asset/ip/report/summary"
    headers = {"x-api-key": api_key}

    for ip_address in ip_addresses:

        flags_strings = []

        # skip if a recent entry exists
        if is_ip_info_recent(api_name, ip_address, db_conn):
            continue

        params = {"ip": ip_address}
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

        # hostname
        hostname = result.get("summary", {}).get("connection", {}).get("hostname", "")

        ### build flags string
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

        store_in_db(
            ip_address=ip_address,
            api_name=api_name,
            api_display_name=api_display_name,
            risk="",
            city="",
            state="",
            cc=cc,
            company=result.get("summary", {}).get("connection", {}).get("ip_address_owner", ""),
            isp="",
            as_name="",
            hostname=hostname,
            flags=flags_string,
            raw_json=result,
            db_conn=db_conn,
        )
