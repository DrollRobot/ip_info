# ip_info

A python package for quickly querying IP address information from multiple providers.

In my work as a SOC analyst, I frequently need to look up geolocation and reputation information for IP address. Because results can be inconsistent between providers, I've found the most reliable method is to check multiple providers. But, when you're investigating a security incident, you don't necessarily want to spend the time to check ten different providers.

That's why I made ip_info. It:
- Checks up to 15 free providers in parallel, returns information in just a few seconds.
- Accepts IPv4 and IPv6 addresses.
- Allows for bulk queries. (if the provider allows)
- Validates IP addresses to prevent wasting queries.
- Can parse IPs from text in the clipboard, allowing for easier input of multiple IPs.
- Keeps a local database of all queries to prevent looking up the same IP multiple times.

Examples of the output:

![https://publish-01.obsidian.md/access/4eea2c7a4d66236903a31f38906e45d8/ip_info_images/ip_info-1753236989279.webp]

![https://publish-01.obsidian.md/access/4eea2c7a4d66236903a31f38906e45d8/ip_info_images/ip_info-1753237264743.webp]

![[ip_info-1753239351548.webp]]


# Install

Clone the repository:
```
git clone https://github.com/DrollRobot/ip_info.git
```

In the package root directory, (where pyproject.toml is) run:
```
pip install .
```

Or, if you use poetry:
```
poetry install
```


# Usage

### Looking up IPs:

You can enter IP addresses on the command line:
![[ip_info-1753415554661.webp]]

If you don't enter any IPs, the script will parse the text in the clipboard looking for IP addresses. Invalid and reserved IPs will be discarded.
![[ip_info-1753417887180.webp]]

### Output format

You can view the results in table format with `--output table`: (default)
![[ip_info-1753417991342.webp]]

Or, view the raw json with `--output json`:
![[ip_info-1753418532254.webp]]

### Choosing which APIs to query

By default, the package queries any API that has keys saved in the keyring, and any that don't require keys.

To query specific APIs, use `--apis <api name>':
![[ip_info-1753420108640.webp]]

Note: The output will show data from all APIs that have queries saved in the database for the given IP.

### Entering API keys

The package uses the keyring library to store your API keys encrypted at rest.

4 of the 14 providers don't require API keys. To access the other providers, you'll have to register for an API key. (see below for information about providiers)

To enter a new API key, run ip_info_keys and enter the api number:
![[ip_info-1753415093128.webp]]

Select 2 to set a new key:
![[ip_info-1753415202218.webp]]

Enter the key:
![[ip_info-1753415243399.webp]]

# APIs

### AbstractAPI.com

- High rate limit (1 per second)

https://app.abstractapi.com/users/signup

### AbuseIPDB.com

- Abuse reports
- High rate limit. (1k per day)

- Doesn't provide location info

https://www.abuseipdb.com/register?plan=free

### CriminalIP.io

- Good security information

- Low Rate limit. (50 per month)

https://www.criminalip.io/register

### IP-API.com

- No registration/key required
- High rate limit.
- Allows bulk queries.

### IP2Location.io (same as IP2Location.com)

- No registration/key required. (but higher rate limit if you do)
- High rate limit. (1k per day, higher with key)

- Only location, asn, proxy

https://www.ip2location.io/sign-up?ref=5

### IPAPI.co

- No registration/key required.
- High rate limit. (1k per day)
- Allows bulk queries

- Only location, asn

### IPAPI.com

- Low rate limit. (100 per month)
- Location only

https://ipapi.com/signup/free

### IPAPI.is

- Provides security and risk information.
- High rate limits. (1k per day)
- Allows bulk queries

https://ipapi.is/app/signup

### IPAPI.org

- High rate limit. (1k per day)
- Allows bulk queries.

https://members.ipapi.org/registration_form.php

### IPGeolocation.io

- High rate limit. (1k per day)

- Only provides location info

https://app.ipgeolocation.io/signup

### IPInfo.io

- No rate limit

- Only location info

https://ipinfo.io/signup

### IPQuery.io

- No registration/key required.
- High rate limit.
- Allows bulk queries
- Good security information

### IPRegistry.co

- Good security information

- Limited queries (100k per account)

https://dashboard.ipregistry.co/signup

### VirusTotal.com

- Good security information
- A trusted provider.

- Low rate limit. (4 per min, 500 per day)

https://www.virustotal.com/gui/join-us


# Contributing

Please contribute! I'm not a professional developer, so this project is a learning experience for me. I welcome constructive feedback

Can't code? Help me find new APIs to add to the script. A good API will have at least one of the following:
- Doesn't require registration/an API key.
- High rate limit. (1k queries per day?)
- Provides good information, like tor/VPN, a risk score, abuse reports, etc...

Provide me with:
- Link to information about their free plan
- Link to API documentation
- Link to registration page, if applicable.