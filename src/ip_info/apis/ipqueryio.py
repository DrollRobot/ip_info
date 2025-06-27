import requests
import sqlite3

from ip_info.db import delete_from_db, is_ip_info_recent, store_in_db

def ipqueryio(ip_addresses, db_conn: sqlite3.Connection = None):

    max_chunk_size = 10000
    api_name = "ipqueryio"
    api_display_name = "IPQuery.io"
    url_base = "https://api.ipquery.io"

    # filter out ips with recent entries in database
    ips_to_query = [ip for ip in ip_addresses if not is_ip_info_recent(api_name, ip, db_conn)]
    if not ips_to_query:
        return

    for i in range(0, len(ips_to_query), max_chunk_size):

        chunk = ips_to_query[i : i + max_chunk_size]
        ips_param = ",".join(chunk)

        url = f"{url_base}/{ips_param}"

        try:
            if len(chunk) == 1:
                print(f"Querying {api_display_name} for {chunk[0]}.")
            else:
                print(f"Querying {api_display_name} for {len(chunk)} IPs.")
            response = requests.get(url)
            response.raise_for_status()
            results = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error querying {api_display_name}: {e}")
            return

        # 3. Normalize single vs bulk response
        records = results if isinstance(results, list) else [results]

        for result in records:

            ip_address = result.get("ip")
            flags_strings = []

            delete_from_db(api_name, ip_address, db_conn)

            ### build flags string
            # datacenter
            if result.get("risk", {}).get("is_datacenter", {}):
                flags_strings.append("datacenter")

            # mobile
            if result.get("risk", {}).get("is_mobile", {}):
                flags_strings.append("mobile")

            # proxy
            if result.get("risk", {}).get("is_proxy", {}):
                flags_strings.append("proxy")

            # risk
            risk = result.get("risk", {}).get("risk_score", {})
            if risk != 0:
                flags_strings.append(f"risk:{risk}")

            # tor
            if result.get("risk", {}).get("is_tor", {}):
                flags_strings.append("tor")

            # vpn
            if result.get("risk", {}).get("is_vpn", {}):
                flags_strings.append("vpn")

            if flags_strings:
                flags_string = ", ".join(flags_strings)
            else:
                flags_string = "-"

            store_in_db(
                ip_address=ip_address,
                api_name=api_name,
                api_display_name=api_display_name,
                risk=result.get("risk", {}).get("risk_score", 0),
                city=result.get("location", {}).get("city", ""),
                state=result.get("location", {}).get("state", ""),
                cc=result.get("location", {}).get("country_code", ""),
                company=result.get("isp", {}).get("org", ""),
                isp=result.get("isp", {}).get("isp", ""),
                as_name=result.get("isp", {}).get("asn", ""),
                hostname="",
                flags=flags_string,
                raw_json=result,
                db_conn=db_conn,
            )