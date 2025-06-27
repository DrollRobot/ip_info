import requests
import sqlite3

from ip_info.db import delete_from_db, is_ip_info_recent, store_in_db

def abuseipdbcom(ip_addresses, api_key, db_conn: sqlite3.Connection = None):

    api_name = "abuseipdbcom"
    api_display_name = "AbuseIPDB.com"
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": api_key}

    for ip_address in ip_addresses:
        flags_strings = []

        # skip if a recent entry exists
        if is_ip_info_recent(api_name, ip_address, db_conn):
            continue

        params = {"ipAddress": ip_address, "maxAgeInDays": "365"}
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
        hostnames = result.get("data", {}).get("hostnames", "")
        if hostnames:
            hostname = hostnames[0]
        else:
            hostname = None

        ### build flags string
        # reports
        reports = result.get("data", {}).get("totalReports", 0)
        if reports != 0:
            flags_strings.append(f"reports:{reports}")

        # risk
        risk = result.get("data", {}).get("abuseConfidenceScore", 0)
        if risk != 0:
            flags_strings.append(f"risk:{risk}")

        # tor
        if result.get("data", {}).get("isTor", {}):
            flags_strings.append("tor")

        if flags_strings:
            flags_string = ", ".join(flags_strings)
        else:
            flags_string = "-"

        store_in_db(
            ip_address=ip_address,
            api_name=api_name,
            api_display_name=api_display_name,
            risk=risk,
            city="",
            state="",
            cc=result.get("data", {}).get("countryCode", ""),
            company=result.get("data", {}).get("isp", ""),
            isp=result.get("data", {}).get("isp", ""),
            as_name="",
            hostname=hostname,
            flags=flags_string,
            raw_json=result,
            db_conn=db_conn,
        )