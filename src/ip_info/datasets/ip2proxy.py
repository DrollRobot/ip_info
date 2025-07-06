import argparse
import csv
import datetime
import ipaddress
import os
import sqlite3
import time

from ip_info.config import DB_PATH
from ip_info.db._initialize_db import initialize_db, ensure_columns_exist
from ip_info.db._add_to_db import _insert_ip_info


def import_ip2proxy(file_path, chunk_size: int = 5000):

    api_name = "ip2proxy"
    api_display_name = "IP2Proxy"
    PROXY_TYPE_MAP = {
        "VPN": "vpn",
        "TOR": "tor",
        "DCH": "hosting",
        "PUB": "public",
        "WEB": "web",
        "SES": "search_spider",
        "RES": "residential",
        "CPN": "consumer",
        "EPN": "enterprise",
    }
    USAGE_TYPE_MAP = {
        "COM": "commercial",
        "ORG": "organization",
        "GOV": "government",
        "MIL": "military",
        "EDU": "school",
        "LIB": "library",
        "CDN": "cdn",
        "ISP": "isp",
        "MOB": "mobile",
        "DCH": "hosting",
        "SES": "search_spider",
        "RSV": "reserved",
    }

    # validate file name
    allowed_file_names = {
        "IP2PROXY-LITE-PX12.CSV",
        "IP2PROXY-LITE-PX12.IPV6.CSV",
    }
    file_name = os.path.basename(file_path).upper()
    if file_name not in allowed_file_names:
        raise ValueError(
            f"Invalid file name '{file_name}'. Must be one of: {', '.join(sorted(allowed_file_names))}"
        )
    
    # open database connection
    db_conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    try:
        # Ensure DB schema
        initialize_db(db_conn=db_conn)
        ensure_columns_exist(db_conn=db_conn)

        start_time = time.time()
        processed_rows = 0
        batch = []

        # open csv file
        with open(file_path, newline="", encoding="utf-8") as csvfile:

            # count lines
            total_rows = sum(1 for _ in csvfile)
            csvfile.seek(0)

            reader = csv.reader(csvfile)

            for row in reader:
                if not row or len(row) < 16:
                    continue

                processed_rows += 1

                # extract row data
                (
                    start_ip_string,
                    end_ip_string,
                    proxy_type,
                    country_code,
                    _country_name,
                    region,
                    city,
                    isp,
                    domain,
                    usage_type,
                    _asn_num,
                    as_name,
                    _last_seen,
                    threat_type,
                    provider,
                    fraud_score,
                ) = row

                # convert bounds to ints
                start_ip_int = int(start_ip_string)
                end_ip_int   = int(end_ip_string)

                ### build flags list
                flags_strings = []

                # proxy type
                if proxy_type:
                    proxy_full = PROXY_TYPE_MAP.get(proxy_type, proxy_type)
                    flags_strings.append(f"proxy:{proxy_full}")

                # usage type
                if usage_type:
                    usage_full = USAGE_TYPE_MAP.get(usage_type, usage_type)
                    flags_strings.append(f"usage:{usage_full}")
                
                # threat type
                if threat_type:
                    flags_strings.append(f"threat:{threat_type}")

                if flags_strings:
                    flags_string = ", ".join(flags_strings)
                else:
                    flags_string = "-"

                # parse fraud_score into an integer risk
                try:
                    risk = int(fraud_score)
                except (ValueError, TypeError):
                    risk = 0

                # iterate through every ip in range
                ts = datetime.datetime.now().astimezone()
                for ip_int in range(start_ip_int, end_ip_int + 1):
                        batch.append({
                            "timestamp":        ts,
                            "ip_address":       str(ipaddress.ip_address(ip_int)),
                            "api_name":         api_name,
                            "api_display_name": api_display_name,
                            "risk":             risk,
                            "city":             city,
                            "state":            region,
                            "cc":               country_code,
                            "company":          provider,
                            "isp":              isp,
                            "as_name":          as_name,
                            "hostname":         domain,
                            "flags":            flags_string,
                            "raw_json":         {},
                        })

                # flush every chunk_size CSV rows
                if processed_rows % chunk_size == 0:
                    _insert_ip_info(entries=batch, db_conn=db_conn)
                    batch.clear()

                # optional progress/ETA
                if processed_rows % chunk_size == 0 or processed_rows == total_rows:
                    elapsed = time.time() - start_time
                    avg_row = elapsed / processed_rows
                    remaining = total_rows - processed_rows
                    eta = datetime.timedelta(seconds=int(avg_row * remaining))
                    elapsed_td = datetime.timedelta(seconds=int(elapsed))
                    print(
                        f"Importing {api_display_name}: "
                        f"{processed_rows}/{total_rows} rows — "
                        f"Elapsed: {elapsed_td} — ETA: {eta}",
                        end="\r",
                        flush=True
                    )

        # final flush of any leftover entries
        if batch:
            _insert_ip_info(entries=batch, db_conn=db_conn)

        # finish with a newline so the shell prompt appears correctly
        print()

    finally:
        db_conn.close()


def cli():
    parser = argparse.ArgumentParser(
        description="Import IP2Proxy‑LITE‑PX12 CSV into the database"
    )
    parser.add_argument(
        "file_path_pos",
        nargs="*",
        help="Path to IP2PROXY‑LITE‑PX12.CSV or IP2PROXY‑LITE‑PX12.IPV6.CSV"
    )
    parser.add_argument(
        "--file_path",
        dest = "file_path_arg",
        help="Path to IP2PROXY‑LITE‑PX12.CSV or IP2PROXY‑LITE‑PX12.IPV6.CSV"
    )

    args = parser.parse_args()

    # parse path named and positional parameters
    file_path = args.file_path_arg if args.file_path_arg else args.file_path_pos

    import_ip2proxy(file_path)

if __name__ == "__main__":
    cli()