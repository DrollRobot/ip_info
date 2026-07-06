"""Interactive keyring-backed manager for storing and retrieving provider API keys."""

import getpass

import keyring
from keyring.errors import PasswordDeleteError

from ip_info.config import API_METADATA

_KEYRING_SERVICE = "ip_info"


def _get_api_key(api_name: str) -> str | None:
    return keyring.get_password(f"{_KEYRING_SERVICE}-{api_name}", "default")


def _set_api_key(api_name: str, api_key: str) -> None:
    keyring.set_password(f"{_KEYRING_SERVICE}-{api_name}", "default", api_key)


def _delete_api_key(api_name: str) -> bool:
    try:
        keyring.delete_password(f"{_KEYRING_SERVICE}-{api_name}", "default")
        return True
    except PasswordDeleteError:
        return False


def ip_info_keys() -> None:
    """Interactive terminal menu for viewing or updating API keys."""
    api_names: list[str] = list(API_METADATA.keys())

    while True:
        print("\n=== API KEY MANAGER ===")
        for index, api_name in enumerate(api_names, 1):
            name = API_METADATA[api_name]["api_display_name"]
            print(f"{index}. {name}")
        print("q. Quit")

        sel = input("Select an API: ").strip().lower()
        if sel in {"q", "quit", "exit"}:
            print("Done.")
            break

        try:
            api_index = int(sel) - 1
            api_name = api_names[api_index]
        except ValueError, IndexError:
            print("⚠️  Invalid choice.")
            continue

        display_name = API_METADATA[api_name]["api_display_name"]
        while True:
            print(f"\n--- {display_name} ---")
            print("1. Show stored key")
            print("2. Set / replace key")
            print("3. Delete key")
            print("b. Back")

            action = input("Choose an option: ").strip().lower()
            if action == "1":
                key = _get_api_key(api_name)
                print(f"Current key: {key or 'No key stored.'}")
            elif action == "2":
                new_key = getpass.getpass("Enter new key (input hidden): ").strip()
                if new_key:
                    _set_api_key(api_name, new_key)
                    print("✅ Key saved.")
                else:
                    print("⚠️  Empty key - nothing saved.")
            elif action == "3":
                confirm = input(f"Delete key for {display_name}? [y/N]: ").strip().lower()
                if confirm == "y":
                    if _delete_api_key(api_name):
                        print("🗑️  Key deleted.")
                    else:
                        print("⚠️  No key stored.")
            elif action in {"b", "back"}:
                break
            else:
                print("⚠️  Invalid choice.")


if __name__ == "__main__":
    ip_info_keys()
