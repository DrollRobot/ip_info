import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import sqlite3
import sys
from importlib.metadata import version, PackageNotFoundError
import traceback
from typing import cast 

from ip_info import __version__
from ip_info._ask_yn import ask_yn
from ip_info._display_ip_info import display_ip_info
from ip_info._parse_clipboard import parse_clipboard
from ip_info._validate_ip_addresses import _validate_ip_addresses
from ip_info.apis.abstractapicom import abstractapicom  # noqa: F401
from ip_info.apis.abuseipdbcom import abuseipdbcom  # noqa: F401
from ip_info.apis.criminalipio import criminalipio  # noqa: F401
from ip_info.apis.ipdashapicom import ipdashapicom  # noqa: F401
from ip_info.apis.ip2locationio import ip2locationio  # noqa: F401
from ip_info.apis.ipapico import ipapico  # noqa: F401
from ip_info.apis.ipapicom import ipapicom  # noqa: F401
from ip_info.apis.ipapiis import ipapiis  # noqa: F401
from ip_info.apis.ipapiorg import ipapiorg  # noqa: F401
from ip_info.apis.ipgeolocationio import ipgeolocationio  # noqa: F401
from ip_info.apis.ipinfoio import ipinfoio  # noqa: F401
from ip_info.apis.ipqueryio import ipqueryio  # noqa: F401
from ip_info.apis.ipregistryco import ipregistryco  # noqa: F401
from ip_info.apis.virustotalcom import virustotalcom  # noqa: F401
from ip_info.config import DB_PATH, API_METADATA
from ip_info.db._initialize_db import initialize_db, ensure_columns_exist
from ip_info.keys import _get_api_key

  
def run_api_function_threadsafe(
    api_function,
    api_name: str,
    api_display_name: str,
    ip_addresses,
    rate_limits,
    api_key,
):
    db_conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    try:
        api_function(
            api_name=api_name,
            api_display_name=api_display_name,
            ip_addresses=ip_addresses,
            rate_limits=rate_limits,
            api_key=api_key,
            db_conn=db_conn,
        )
    except Exception:
        print(f"[ERROR] Exception in thread for {api_name}")
        traceback.print_exc()
    finally:
        db_conn.close()


def main(
    *, 
    user_input: list[str], 
    query_apis: list[str], 
    output_format="table"
    ):

    # display package version for user
    print(f"Package version: {__version__}")

    # open database
    db_conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)

    try:
        # verify the database schema is correct
        initialize_db(db_conn=db_conn)
        ensure_columns_exist(db_conn=db_conn)

        # if input supplied as cli argument
        if user_input:
            ip_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = _validate_ip_addresses(
                user_input=user_input, 
                verbose=True
            )
        # if no cli input, check clipboard
        else:
            user_input = parse_clipboard()
            if not user_input:
                sys.exit("No IP addresses supplied and none detected in clipboard.")

            ip_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = _validate_ip_addresses(
                user_input=user_input, 
                verbose=False
            )
            ip_addresses_string: list[str] = [str(ip) for ip in ip_addresses]
            print(f"Found in clipboard: {ip_addresses_string}")
            if ask_yn("Query these IPs?", true="n"):
                sys.exit("No IP addresses supplied and none detected in clipboard.")

        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = []

            # loop through each api and create thread
            for api_name in query_apis:
                api_metadata = API_METADATA.get(api_name)
                if not api_metadata:
                    print(f"Unknown API '{api_name}' - skipping")
                    continue

                api_display_name = api_metadata["api_display_name"]
                rate_limits = api_metadata["rate_limits"]
                requires_key = api_metadata["requires_key"]

                api_key = _get_api_key(api_name)
                if not api_key and requires_key:
                    continue

                api_function = globals().get(api_name)
                if api_function is None:
                    print(f"No implementation found for {api_name}")
                    continue

                futures.append(
                    executor.submit(
                        run_api_function_threadsafe,
                        api_function,
                        api_name,
                        api_display_name,
                        ip_addresses,
                        rate_limits,
                        api_key,
                    )
                )

            # wait for all threads to finish
            for future in futures:
                future.result()  # triggers any exceptions

        print("")

        # retrieve ip info from database and display for user
        display_ip_info(
            ip_addresses=ip_addresses,
            db_conn=db_conn,
            output_format=output_format,
        )

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
        choices = ["all", "bulk", "none"] + list(API_METADATA.keys()),
        default = ["all"],
        help = "Comma separated list of APIs to query."
    )
    
    args = parser.parse_args()

    # parse ips from positional or named argument, normalize to list
    user_input = cast(list[str], args.ip_addresses_arg or args.ip_addresses_pos)

    # set query_apis
    if args.query_apis == ["all"]:
        args.query_apis = list(API_METADATA.keys())
    elif args.query_apis == ["bulk"]:
        args.query_apis = [
            api_name
            for api_name, api_information in API_METADATA.items()
            if api_information["allows_bulk"]
        ]
    elif args.query_apis == ["none"]:
        args.query_apis = []
    
    main(
        user_input = user_input,
        query_apis = args.query_apis,
        output_format = args.output_format
    )

if __name__ == "__main__":
    cli()
