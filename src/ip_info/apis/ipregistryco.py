import requests
import sqlite3

from ip_info.db import delete_from_db, is_ip_info_recent, store_in_db

def ipregistryco(ip_addresses, api_key, db_conn: sqlite3.Connection = None):

    api_name = "ipregistryco"
    api_display_name = "IPRegistry.co"
    max_chunk_size = 1024
    params = {"key": api_key}

    # filter out ips that already have a recent db entry
    ips_to_query = [ip for ip in ip_addresses if not is_ip_info_recent(api_name, ip, db_conn)]
    if not ips_to_query:
        return
    
    for i in range(0, len(ips_to_query), max_chunk_size):

        chunk = ips_to_query[i : i + max_chunk_size]
        ips_param = ",".join(chunk)

        url = f"https://api.ipregistry.co/{ips_param}"

        try:
            if len(chunk) == 1:
                print(f"Querying {api_display_name} for {chunk[0]}.")
            else:
                print(f"Querying {api_display_name} for {len(chunk)} IPs.")
            response = requests.get(url, params=params)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error querying {api_display_name}: {e}")
            return

        results = data.get("results", [])
        # handle single‑record endpoint (no 'results' field)
        if not results and isinstance(data, dict) and "security" in data:
            results = [data]

        for result in results:
            ip_address = result.get("ip") or result.get("ip_address")
            if not ip_address:
                continue

            flags_strings = []

            delete_from_db(api_name, ip_address, db_conn)

            ### build flags string
            # abuse
            if result.get("security", {}).get("is_abuser", {}):
                flags_strings.append("abuse")

            # anonymous
            if result.get("security", {}).get("is_anonymous", {}):
                flags_strings.append("anonymous")

            # attacker
            if result.get("security", {}).get("is_attacker", {}):
                flags_strings.append("anoattackernymous")

            # bogon
            if result.get("security", {}).get("is_bogon", {}):
                flags_strings.append("bogon")

            # cloud
            if result.get("security", {}).get("is_cloud_provider", {}):
                flags_strings.append("cloud")

            # proxy
            if result.get("security", {}).get("is_proxy", {}):
                flags_strings.append("proxy")

            # relay
            if result.get("security", {}).get("is_relay", {}):
                flags_strings.append("relay")

            # threat
            if result.get("security", {}).get("is_threat", {}):
                flags_strings.append("threat")

            # tor
            tor = result.get("security", {}).get("is_tor", {})
            tor_exit = result.get("security", {}).get("is_tor_exit", {})
            if tor or tor_exit:
                flags_strings.append("tor")

            # vpn
            if result.get("security", {}).get("is_vpn", {}):
                flags_strings.append("vpn")

            if flags_strings:
                unique_flags_strings = list(dict.fromkeys(flags_strings))
                flags_string = ", ".join(unique_flags_strings)
            else:
                flags_string = "-"

            store_in_db(
                ip_address=ip_address,
                api_name=api_name,
                api_display_name=api_display_name,
                risk="",
                city=result.get("location", "").get("city", ""),
                state=result.get("location", "").get("region", "").get("name", ""),
                cc=result.get("location", "").get("country", "").get("code", ""),
                company=result.get("company", {}).get("name", ""),
                isp="",
                as_name=result.get("connection", "").get("organization", ""),
                hostname="",
                flags=flags_string,
                raw_json=result,
                db_conn=db_conn,
            )