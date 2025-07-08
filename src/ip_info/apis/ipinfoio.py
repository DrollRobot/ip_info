import ipaddress
import ipinfo
import sqlite3
from datetime import datetime
from typing import Dict

from ip_info.config import LOCAL_TIMEZONE
from ip_info.db._add_to_db import _insert_ip_info
from ip_info.db._query_db import _is_db_entry_recent


def ipinfoio(
    *,
    api_name: str,
    api_display_name: str,
    ip_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    rate_limits: list[Dict], # FIXME figure out how to implement rate limit checking with ipinfo package
    api_key: str,
    db_conn: sqlite3.Connection
) -> None:
    
    # filter out ips with recent entries in database
    ips_to_query = [ip for ip in ip_addresses if not _is_db_entry_recent(api_name, ip, db_conn)]
    if not ips_to_query:
        return
    
    ip_strings = [str(ip) for ip in ips_to_query]

    
    # build request params
    handler = ipinfo.getHandler(
        api_key,
        request_options={"timeout": 5},
    )

    try:
        if len(ips_to_query) == 1:
            print(f"Querying {api_display_name} for {ips_to_query[0]}")
        else:
            print(f"Querying {api_display_name} for {len(ips_to_query)} IPs")
        results = handler.getBatchDetails(ip_strings)

    except Exception as error:
        # includes RequestQuotaExceededError, TimeoutExceededError, etc.
        print(f"Error querying {api_display_name}: {error}")
        return

    # save query time for ip database timestamp
    last_request_time = datetime.now(LOCAL_TIMEZONE)

    for query_ip, result in results.items():

            # split as and company
            org = result.get("org", "")
            parts = org.split(maxsplit=1)
            as_name  = parts[0] if parts and parts[0].startswith("AS") else ""
            company  = parts[1] if len(parts) > 1 else ""

            entry = {
                "timestamp":   last_request_time,
                "ip_address":  query_ip,
                "api_name":    api_name,
                "api_display_name": api_display_name,
                "risk":        "",
                "city":        result.get("city", ""),
                "state":       result.get("region", ""),
                "cc":          result.get("country", ""),
                "company":     company,
                "isp":         "",
                "as_name":     as_name,
                "hostname":    result.get("hostname", ""),
                "flags":       "",
                "raw_json":    result,
            }
            _insert_ip_info(entries=[entry], db_conn=db_conn)