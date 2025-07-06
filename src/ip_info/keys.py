import getpass
import keyring

from ip_info.config import API_METADATA

_KEYRING_SERVICE = "ip_info"


def _get_api_key(api_name: str) -> str | None:
    """Return stored key for *api_id* (or None if unset)."""
    return keyring.get_password(_KEYRING_SERVICE, api_name)

def _set_api_key(api_name: str, api_key: str) -> None:
    """Save / overwrite *api_key* for *api_id*."""
    keyring.set_password(_KEYRING_SERVICE, api_name, api_key)


def ip_info_keys() -> None:
    """
    Interactive terminal menu for viewing or updating API keys.
    """

    api_ids = [
        api_id
        for api_id, meta in API_METADATA.items()
        if meta.get("requires_key", False)
    ]

    while True:
        print("\n=== API KEY MANAGER ===")
        for idx, api_id in enumerate(api_ids, 1):
            name = API_METADATA[api_id]["api_display_name"]
            print(f"{idx}. {name}")
        print("q. Quit")

        sel = input("Select an API: ").strip().lower()
        if sel in {"q", "quit", "exit"}:
            print("Done.")
            break

        try:
            api_idx = int(sel) - 1
            api_id = api_ids[api_idx]
        except (ValueError, IndexError):
            print("⚠️  Invalid choice.")
            continue

        display_name = API_METADATA[api_id]["api_display_name"]
        while True:
            print(f"\n--- {display_name} ---")
            print("1. Show stored key")
            print("2. Set / replace key")
            print("b. Back")

            action = input("Choose an option: ").strip().lower()
            if action == "1":
                key = _get_api_key(api_id)
                print(f"Current key: {key or 'No key stored.'}")
            elif action == "2":
                new_key = getpass.getpass("Enter new key (input hidden): ").strip()
                if new_key:
                    _set_api_key(api_id, new_key)
                    print("✓ Key saved.")
                else:
                    print("⚠️  Empty key - nothing saved.")
            elif action in {"b", "back"}:
                break
            else:
                print("⚠️  Invalid option.")


if __name__ == "__main__":
    ip_info_keys()