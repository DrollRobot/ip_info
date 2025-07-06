import json
import sqlite3
import tabulate
from typing import Iterable

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

def _display_ip_info(
    *,
    ip_addresses: Iterable[str],
    output_format: str,
    db_conn: sqlite3.Connection,
) -> None:
    """
    print the stored api results for each ip in *ip_addresses*.

    Args:
        ip_addresses: one or more ip strings
        db_conn:     open sqlite connection to the ip_info.db
        output_format:
            - "json"  → pretty-print raw JSON for every api row
            - "table" → compact tabular summary (default)
            - "none"  → do nothing
    """

    for ip_address in ip_addresses:
        print(f"Results for {ip_address}")
        rows = _fetch_ip_info("all", ip_address, db_conn=db_conn)

        if not rows:
            print(f"No data for {ip_address}.")
            continue

        if output_format == "json":
            for row in rows:
                ts   = _format_timestamp(row["timestamp"])
                disp = row["api_display_name"]
                print(f"Showing raw JSON return for {ip_address} from {disp} on {ts}")
                print(json.dumps(json.loads(row.get("raw_json", {})), indent=4))

        elif output_format == "table":

            for row in rows:
                # format timestamps for display
                row["timestamp"] = _format_timestamp(row["timestamp"])
                # condense company/isp/asn/hostname
                row["ownership"] = _format_ownership(row)

            # build table from database rows
            table = []
            for row in rows:
                formatted_row = []
                for column_name in DISPLAY_COLUMNS:
                    value = row.get(column_name, "")
                    formatted_row.append(value)
                table.append(formatted_row)

            # display table with tabulate
            tabulate.MIN_PADDING = 0
            print(
                tabulate.tabulate(
                    table,
                    headers=DISPLAY_COLUMNS,
                    tablefmt="simple_outline",
                    stralign="left",
                )
            )