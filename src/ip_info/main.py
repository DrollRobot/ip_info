import argparse
from importlib.metadata import version, PackageNotFoundError
import json
import sqlite3
from tabulate import tabulate

from ip_info.db import initialize_db, ensure_columns_exist, fetch_ip_info, DB_PATH
from ip_info.format_timestamp import format_timestamp
from ip_info.load_api_keys import load_api_keys
from ip_info.validate_ip_addresses import validate_ip_addresses

# api query functions
from ip_info.apis.abstractapicom import abstractapicom
from ip_info.apis.abuseipdbcom import abuseipdbcom
from ip_info.apis.criminalipio import criminalipio
from ip_info.apis.ipdashapicom import ipdashapicom
from ip_info.apis.ip2locationio import ip2locationio
from ip_info.apis.ipapico import ipapico
from ip_info.apis.ipapicom import ipapicom
from ip_info.apis.ipapiis import ipapiis
from ip_info.apis.ipapiorg import ipapiorg
from ip_info.apis.ipgeolocationio import ipgeolocationio
from ip_info.apis.ipinfoio import ipinfoio
from ip_info.apis.ipqueryio import ipqueryio
from ip_info.apis.ipregistryco import ipregistryco
from ip_info.apis.virustotalcom import virustotalcom


BULK_QUERY_APIS = [
    "ipapiis",
    "ipapiorg",
    "ipdashapicom",
    "ipqueryio",
    "ipregistryco",
]
SINGLE_QUERY_APIS = [
    "abstractapicom",
    "abuseipdbcom",
    "criminalipio",
    "ip2locationio",
    "ipapico",
    "ipapicom",
    "ipgeolocationio",
    "ipinfoio",
    "virustotalcom",
]
ALL_APIS = BULK_QUERY_APIS + SINGLE_QUERY_APIS
ALL_APIS.sort()

DISPLAY_COLUMNS = [
    "api_display_name",
    "city",
    "state",
    "cc",
    "company",
    "isp",
    "as_name",
    "flags",
]

def get_package_version() -> str:
    try:
        return version("ip_info")
    except PackageNotFoundError:
        return "version not found"

def main(*, ip_addresses=None, query_apis, output_format="table", api_keys_file=None):

    # display package version for user
    print(f"Package version: {get_package_version()}")

    # open database
    db_conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    try:
        # Ensure DB schema
        initialize_db(db_conn=db_conn)
        ensure_columns_exist(db_conn=db_conn)

        # Load API keys and validate inputs
        api_keys = load_api_keys(file_path=api_keys_file)
        ip_addresses = validate_ip_addresses(ip_addresses, verbose=True)

        # Query each API, passing the shared connection
        for api_name in query_apis:
            if api_name == "abstractapicom":
                key = api_keys.get(api_name)
                if key:
                    abstractapicom(ip_addresses, key, db_conn=db_conn)
                else:
                    print(f"No API key for {api_name}")

            elif api_name == "abuseipdbcom":
                key = api_keys.get(api_name)
                if key:
                    abuseipdbcom(ip_addresses, key, db_conn=db_conn)
                else:
                    print(f"No API key for {api_name}")

            elif api_name == "criminalipio":
                key = api_keys.get(api_name)
                if key:
                    criminalipio(ip_addresses, key, db_conn=db_conn)
                else:
                    print(f"No API key for {api_name}")

            elif api_name == "ipdashapicom":
                ipdashapicom(ip_addresses, db_conn=db_conn)

            elif api_name == "ip2locationio":
                key = api_keys.get(api_name)
                if key:
                    ip2locationio(ip_addresses, key, db_conn=db_conn)
                else:
                    print(f"No API key for {api_name}")

            elif api_name == "ipapico":
                ipapico(ip_addresses, db_conn=db_conn)

            elif api_name == "ipapicom":
                key = api_keys.get(api_name)
                if key:
                    ipapicom(ip_addresses, key, db_conn=db_conn)
                else:
                    print(f"No API key for {api_name}")

            elif api_name == "ipapiis":
                key = api_keys.get(api_name)
                if key:
                    ipapiis(ip_addresses, key, db_conn=db_conn)
                else:
                    print(f"No API key for {api_name}")

            elif api_name == "ipapiorg":
                key = api_keys.get(api_name)
                if key:
                    ipapiorg(ip_addresses, key, db_conn=db_conn)
                else:
                    print(f"No API key for {api_name}")

            elif api_name == "ipgeolocationio":
                key = api_keys.get(api_name)
                if key:
                    ipgeolocationio(ip_addresses, key, db_conn=db_conn)
                else:
                    print(f"No API key for {api_name}")

            elif api_name == "ipinfoio":
                key = api_keys.get(api_name)
                if key:
                    ipinfoio(ip_addresses, key, db_conn=db_conn)
                else:
                    print(f"No API key for {api_name}")

            elif api_name == "ipqueryio":
                ipqueryio(ip_addresses, db_conn=db_conn)

            elif api_name == "ipregistryco":
                key = api_keys.get(api_name)
                if key:
                    ipregistryco(ip_addresses, key, db_conn=db_conn)
                else:
                    print(f"No API key for {api_name}")

            elif api_name == "virustotalcom":
                key = api_keys.get(api_name)
                if key:
                    virustotalcom(ip_addresses, key, db_conn=db_conn)
                else:
                    print(f"No API key for {api_name}")

            else:
                continue

        print("")

        # Display results for each IP
        for ip_address in ip_addresses:
            print(f"Results for {ip_address}")
            rows = fetch_ip_info("all", ip_address, db_conn=db_conn)

            if output_format == "json":
                for row in rows:
                    ts = format_timestamp(row["timestamp"])
                    disp = row["api_display_name"]
                    print(f"Showing raw JSON return for {ip_address} from {disp} on {ts}")
                    print(json.dumps(json.loads(row.get("raw_json", {})), indent=4))

            elif output_format == "table":
                if rows:
                    # Format timestamps
                    for r in rows:
                        r["timestamp"] = format_timestamp(r["timestamp"])

                    table = [
                        [
                            r.get(col, "")
                            for col in [
                                "api_display_name",
                                "city",
                                "state",
                                "cc",
                                "company",
                                "isp",
                                "as_name",
                                "flags"
                            ]
                        ]
                        for r in rows
                    ]

                    tabulate.MIN_PADDING = 0
                    print(
                        tabulate(
                            table,
                            headers=[
                                "api_display_name",
                                "city",
                                "state",
                                "cc",
                                "company",
                                "isp",
                                "as_name",
                                "flags"
                            ],
                            tablefmt="simple_outline",
                            stralign="left"
                        )
                    )
                else:
                    print("No data available to display.")

    finally:
        # Ensure the DB connection is closed even on errors or interrupts
        db_conn.close()


def cli():
    parser = argparse.ArgumentParser(
        description = "Query IP reputation APIs and store responses."
    )
    parser.add_argument(
        "ip_addresses_pos",
        nargs="*",
        help="The IP address(es) to query. (positional argument)"
    )
    parser.add_argument(
        "--ip",
        "--ips",
        "--ip_address",
        "--ip_addresses",
        dest = "ip_addresses_arg",
        help = "The IP address(es) to query.",
        nargs = '+'
    )
    parser.add_argument(
        "--format",
        "--output_format",
        dest = "output_format",
        choices = ["json", "table", "none"],
        default = "table",
        help = "Output format: json, table, none (query and add to database, but no output)"
    )
    parser.add_argument(
        "--api",
        "--apis",
        "--query_api",
        "--query_apis",
        dest = "query_apis",
        nargs   = "+",
        choices = ["all", "bulk", "none"] + ALL_APIS,
        default = "all",
        help = "Comma separated list of APIs to query."
    )
    parser.add_argument(
        "--keys",
        "--api_keys_file",
        dest="api_keys_file",
        help="Path to your csv file containing api keys. (defaults to the built-in api_keys.csv)",
    )
    
    args = parser.parse_args()

    # parse ips from positional and named arguments
    ip_addresses = args.ip_addresses_arg if args.ip_addresses_arg else args.ip_addresses_pos

    # validate apis
    if args.query_apis == ["all"]:
        args.query_apis = ALL_APIS
    elif args.query_apis == ["bulk"]:
        args.query_apis = BULK_QUERY_APIS
    elif args.query_apis == ["none"]:
        args.query_apis = []
    
    main(
        ip_addresses = ip_addresses,
        query_apis = args.query_apis,
        output_format = args.output_format,
        api_keys_file = args.api_keys_file,
    )

if __name__ == "__main__":
    cli()
