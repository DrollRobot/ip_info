import re
import requests
import sqlite3

from ip_info.db import delete_from_db, is_ip_info_recent, store_in_db

def ipapiis(ip_addresses, api_key, db_conn: sqlite3.Connection = None):

    max_chunk_size = 100
    api_name = "ipapiis"
    api_display_name = "IPAPI.is"
    url = "https://api.ipapi.is"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
    }

    # filter out ips with recent entries in database
    ips_to_query = [ip for ip in ip_addresses if not is_ip_info_recent(api_name, ip, db_conn)]
    if not ips_to_query:
        return

    # split ips into chunks
    for i in range(0, len(ips_to_query), max_chunk_size):

        chunk = ips_to_query[i : i + max_chunk_size]
        payload = {"ips": chunk, "key": api_key}

        # send query
        try:
            if len(chunk) == 1:
                print(f"Querying {api_display_name} for {chunk[0]}.")
            else:
                print(f"Querying {api_display_name} for {len(chunk)} IPs.")
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()
            results = (
                response.json()
            )  # Expected to be a list containing one response per IP.
        except requests.exceptions.RequestException as e:
            print(f"Error querying {api_display_name} for IPs {chunk}: {e}")
            continue

        # parse results
        for ip_address, result in results.items():
            # skip keys that aren't ip addresses
            if ip_address == "total_elapsed_ms":
                continue

            flags_strings = []

            delete_from_db(api_name, ip_address, db_conn)

            ### build flags string            
            # abuse
            if result.get("is_abuser", {}):
                flags_strings.append("abuse")

            # as_risk
            abuser_score_string = result.get("asn", {}).get("abuser_score", "")
            if abuser_score_string:
                as_risk_string = re.search(r'\((.*?)\)', abuser_score_string).group(1)
                if as_risk_string not in ["Very Low","Low"]:
                    flags_strings.append(f"as_risk:{as_risk_string}")

            # bogon
            if result.get("is_bogon", {}):
                flags_strings.append("bogon")

            # company_risk
            abuser_score_string = result.get("company", {}).get("abuser_score", "")
            if abuser_score_string:
                company_risk_string = re.search(r'\((.*?)\)', abuser_score_string).group(1)
                if company_risk_string not in ["Very Low","Low"]:
                    flags_strings.append(f"as_risk:{company_risk_string}")

            # datacenter
            if result.get("is_datacenter", {}):
                flags_strings.append("datacenter")

            # mobile
            if result.get("is_mobile", {}):
                flags_strings.append("mobile")

            # proxy
            if result.get("is_proxy", {}):
                flags_strings.append("proxy")

            # satellite
            if result.get("is_satellite", {}):
                flags_strings.append("satellite")

            # tor
            if result.get("is_tor", {}):
                flags_strings.append("tor")

            # vpn
            if result.get("is_vpn", {}):
                flags_strings.append("vpn")

            if flags_strings:
                flags_string = ", ".join(flags_strings)
            else:
                flags_string = "-"

            store_in_db(
                ip_address=ip_address,
                api_name=api_name,
                api_display_name=api_display_name,
                risk="",
                city=result.get("location", "").get("city", ""),
                state=result.get("location", "").get("state", ""),
                cc=result.get("location", "").get("country_code", ""),
                company=result.get("company", "").get("name", ""),
                isp="",
                as_name=result.get("asn", "").get("org", ""),
                hostname="",
                flags=flags_string,
                raw_json=result,
                db_conn=db_conn,
            )