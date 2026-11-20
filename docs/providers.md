# Providers

`ip_info` can query the 14 providers below. Four require no registration; the
rest offer a free tier that needs an API key. Use the **name** column with
`--apis` to query a specific provider (see [Usage](usage.md)).

## Adding API keys

API keys are stored in your operating system's credential store (Windows
Credential Manager, macOS Keychain, or the Linux Secret Service), so they are
never kept in the repository or in plain text. The settings file,
`config.toml`, holds only the name each key is stored under.

Each key's setting is the provider's `--apis` name plus `_api_key`. To add or
replace one:

```
ip-info-config set-secret abuseipdbcom_api_key
```

It asks for the storage name (press Enter to accept the default), then for
the key, hidden.

To set up several keys in one pass, run `ip-info-config init`. It asks about
each provider in turn; answer `n` to skip one.

| Task | Command |
|---|---|
| See which keys are set (values masked) | `ip-info-config show` |
| Remove a key | `ip-info-config delete-secret abuseipdbcom_api_key` |
| Find the settings file | `ip-info-config path` |

Every key can also come from an environment variable, `IP_INFO_` plus the
setting name in capitals, such as `IP_INFO_ABUSEIPDBCOM_API_KEY`.

### Upgrading from 1.x

ip_info 1.x stored keys in a different place, under the `ip_info_keys`
command. After upgrading, run this once from a checkout of the repo:

```
git clone https://github.com/DrollRobot/ip_info.git
cd ip_info
uv run scripts/migrate_keys.py
```

It moves each 1.x key to the new location, reads it back to check it, then
deletes the 1.x copy.


## Available providers

| Provider | `--apis` name | Key | Notes |
|---|---|---|---|
| [AbstractAPI.com](https://app.abstractapi.com/users/signup) | `abstractapicom` | Required | High rate limit (1/sec). |
| [AbuseIPDB.com](https://www.abuseipdb.com/register?plan=free) | `abuseipdbcom` | Required | Abuse reports; high limit (1k/day); no location data. |
| [CriminalIP.io](https://www.criminalip.io/register) | `criminalipio` | Required | Good security information; low limit (50/month). |
| [IP-API.com](https://ip-api.com/) | `ipdashapicom` | Not required | High rate limit; supports bulk queries. |
| [IP2Location.io](https://www.ip2location.io/sign-up?ref=5) | `ip2locationio` | Optional | High limit (1k/day, more with a key); location, ASN, proxy only. |
| [IPAPI.co](https://ipapi.co/) | `ipapico` | Not required | High limit (1k/day); bulk; location and ASN only. |
| [IPAPI.com](https://ipapi.com/signup/free) | `ipapicom` | Required | Low limit (100/month); location only. |
| [IPAPI.is](https://ipapi.is/app/signup) | `ipapiis` | Required | Security and risk data; high limit (1k/day); bulk. |
| [IPAPI.org](https://members.ipapi.org/registration_form.php) | `ipapiorg` | Required | High limit (1k/day); bulk. |
| [IPGeolocation.io](https://app.ipgeolocation.io/signup) | `ipgeolocationio` | Required | High limit (1k/day); location only. |
| [IPInfo.io](https://ipinfo.io/signup) | `ipinfoio` | Required | No rate limit; location only. |
| [IPQuery.io](https://ipquery.io/) | `ipqueryio` | Not required | High limit; bulk; good security information. |
| [IPRegistry.co](https://dashboard.ipregistry.co/signup) | `ipregistryco` | Required | Good security information; 100k queries per account. |
| [VirusTotal.com](https://www.virustotal.com/gui/join-us) | `virustotalcom` | Required | Good security information; trusted provider; low limit (4/min, 500/day). |

## Suggesting a provider

Know of a provider that offers API access in a free tier that isn't listed?
Contributions are welcome - see
[CONTRIBUTING.md](https://github.com/DrollRobot/ip_info/blob/main/CONTRIBUTING.md).
Providers that need no key, have a high rate limit, and return good security
information (Tor/VPN detection, risk scores, abuse reports) are especially
useful.
