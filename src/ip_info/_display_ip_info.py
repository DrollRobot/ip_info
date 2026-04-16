import ipaddress
import json
import sqlite3
import tabulate

from ip_info.db._query_db import _fetch_ip_info
from ip_info._format_timestamp import _format_timestamp
from ip_info._format_ownership import _format_ownership

DISPLAY_COLUMNS = [
    "api_display_name",
    "city",
    "state",
    "cc",
    "ownership",
    "flags",
]

def display_ip_info(
    *,
    ip_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    output_format: str,
    db_conn: sqlite3.Connection,
) -> None:
    """
    print the stored api results for each ip in *ip_addresses*.

    Args:
        ip_addresses: one or more ip strings
        db_conn:     open sqlite connection to the ip_info.db
        output_format:
            - "rawjson"   → pretty-print raw JSON for every api row
            - "jsontable" → JSON object keyed by IP with table as value
            - "table"     → compact tabular summary (default)
            - "none"      → do nothing
    """

    jsontable_result = {}

    for ip_address in ip_addresses:
        rows = _fetch_ip_info(
            api_names=["all"],
            ip_address=ip_address, 
            db_conn=db_conn
        )

        if not rows:
            print(f"No data for {ip_address}.")
            continue

        if output_format == "rawjson":
            print(ip_address)
            for row in rows:
                ts   = _format_timestamp(row["timestamp"])
                disp = row["api_display_name"]
                print(f"Showing raw JSON return for {ip_address} from {disp} on {ts}")
                print(json.dumps(json.loads(row.get("raw_json", {})), indent=4))

        elif output_format in ("table", "jsontable"):
            for row in rows:
                # format timestamps for display
                row["timestamp"] = _format_timestamp(row["timestamp"])
                # condense company/isp/asn/hostname
                row["ownership"] = _format_ownership(row)

            # sort rows by api_display_name
            rows.sort(key=lambda row: row.get("api_display_name", "").lower())

            # build table from database rows
            table = []
            for row in rows:
                formatted_row = []
                for column_name in DISPLAY_COLUMNS:
                    value = row.get(column_name, "")
                    formatted_row.append(value)
                table.append(formatted_row)

            # render table with tabulate
            tabulate.MIN_PADDING = 0
            rendered_table = tabulate.tabulate(
                table,
                headers=DISPLAY_COLUMNS,
                # tablefmt="simple_outline",
                tablefmt="github",
                stralign="left",
            )

            if output_format == "table":
                print(ip_address)
                print(rendered_table)
            else:
                jsontable_result[str(ip_address)] = rendered_table

    if output_format == "jsontable":
        print(json.dumps(jsontable_result, indent=4))