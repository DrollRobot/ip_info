from datetime import datetime
import requests
import sqlite3

from ip_info.config import LOCAL_TIMEZONE
from ip_info.db import check_rate_limits, insert_ip_info, insert_query_info, is_ip_info_recent

def abstractapicom(ip_addresses, api_key, db_conn: sqlite3.Connection = None, fields=None):

    api_name = "abstractapicom"
    api_display_name = "AbstractAPI.com"
    url = "https://ip-intelligence.abstractapi.com/v1/"

    for ip_address in ip_addresses:

        flags_strings = []

        # skip if a recent entry exists
        if is_ip_info_recent(api_name, ip_address, db_conn):
            continue

        # check rate limits
        rate_limits = [
            {
                "query_limit":   1,
                "timeframe": "second",
                "type":      "rolling",
                "status_code":  429,
                "error_text":   "Too many requests"
            },
            {
                "query_limit":   1000,
                "timeframe": "day",
                "type":      "absolute",
                "status_code":  422,
                "error_text":   "Quota reached"
            },
        ]
        check_rate_limits(api_name, rate_limits, db_conn)

        # build request parameters
        params = {"api_key": api_key, "ip_address": ip_address}
        if fields:
            params["fields"] = fields

        try:
            print(f"Querying {api_display_name} for {ip_address}")
            response = requests.get(url, params=params)
            insert_query_info(api_name, response, db_conn)


            # rate limit response
            if response.status_code != 200:
                print(f"Received status code {response.status_code}, message {response.text}. Skipping query")
                continue

            response.raise_for_status()
            result = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error querying {api_display_name} for {ip_address}: {e}")
            continue

        # save query time for ip database timestamp
        last_request_time = datetime.now(LOCAL_TIMEZONE)

        ### build flags string
        # abuse
        if result.get("security", {}).get("is_abuse"):
            flags_strings.append("abuse")

        # hosting
        if result.get("security", {}).get("is_hosting"):
            flags_strings.append("hosting")
            
        # mobile
        if result.get("security", {}).get("is_mobile"):
            flags_strings.append("mobile")

        # vpn
        if result.get("security", {}).get("is_vpn"):
            flags_strings.append("vpn")

        # proxy
        if result.get("security", {}).get("is_proxy"):
            flags_strings.append("proxy")

        # relay
        if result.get("security", {}).get("is_relay"):
            flags_strings.append("relay")

        # tor
        if result.get("security", {}).get("is_tor"):
            flags_strings.append("tor")

        if flags_strings:
            flags_string = ", ".join(flags_strings)
        else:
            flags_string = "-"

        entry = {
            "timestamp": last_request_time,
            "ip_address": ip_address,
            "api_name": api_name,
            "api_display_name": api_display_name,
            "risk": "",
            "city": result.get("location", {}).get("city", ""),
            "state": result.get("location", {}).get("region", ""),
            "cc": result.get("location", {}).get("country_code", ""),
            "company": result.get("company", {}).get("name", ""),
            "isp": "",
            "as_name": result.get("asn", {}).get("name", ""),
            "hostname": "",
            "flags": flags_string,
            "raw_json": result
        }
        insert_ip_info(entries=[entry], db_conn=db_conn)
