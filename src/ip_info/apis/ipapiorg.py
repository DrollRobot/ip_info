import requests
# import certifi
import sqlite3

from ip_info.db import delete_from_db, is_ip_info_recent, store_in_db

def ipapiorg(ip_addresses, api_key, db_conn: sqlite3.Connection = None, fields=None):

    api_name = "ipapiorg"
    api_display_name = "IPAPI.org"
    url = "https://pro.ipapi.org/api_json/batch.php"
    MAX_CHUNK_SIZE = 100

    # filter out ips with recent entries in database
    to_query = [ip for ip in ip_addresses if not is_ip_info_recent(api_name, ip, db_conn)]
    if not to_query:
        return

    for i in range(0, len(to_query), MAX_CHUNK_SIZE):

        chunk = to_query[i:i + MAX_CHUNK_SIZE]
        params = {
            "key": api_key,
            "ips": ",".join(chunk)
        }
        if fields:
            params["fields"] = fields

        try:
            if len(chunk) == 1:
                print(f"Querying {api_display_name} for {chunk[0]}.")
            else:
                print(f"Querying {api_display_name} for {len(chunk)} IPs.")
            response = requests.get(url, params=params)#, verify=False)#certifi.where())
            response.raise_for_status()
            results = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error querying {api_display_name}: {e}")
            continue

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
                ip_address = ip_address,
                api_name = api_name,
                api_display_name = api_display_name,
                risk="",
                city=result.get("city", ""),
                state=result.get("regionName", "") or result.get("region", ""),
                cc=result.get("countryCode", ""),
                company=result.get("isp", ""),
                isp="",
                as_name=result.get("as", ""),
                hostname="",
                flags=flags_string,
                raw_json=result,
                db_conn=db_conn,
            )