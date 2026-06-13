"""
Device fingerprinting and User-Agent parsing.

Architecture — what is a device fingerprint?
─────────────────────────────────────────────
  A fingerprint is a stable, short identifier for a "device + network"
  combination, derived WITHOUT storing any PII.

  We hash:
    SHA-256(ip_subnet + "|" + user_agent_string)

  Where ip_subnet is the first 3 octets of the IP (e.g. "192.168.1").
  Using the subnet (not exact IP) means the fingerprint survives DHCP lease
  renewals — your IP changing from .42 to .47 on the same home router still
  looks like the same device.

  The hash is truncated to 64 hex chars — unique enough for our purposes,
  short enough to index efficiently in Postgres.

Why User-Agent parsing?
───────────────────────
  The raw User-Agent string is a long opaque blob like:
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ..."
  The `user_agents` library parses this into structured fields:
    os="Windows 10", browser="Chrome 120", device_type="PC"
  These are human-readable and useful for the audit log / alerts.
"""

import hashlib
from user_agents import parse as ua_parse


def parse_user_agent(ua_string: str) -> dict[str, str]:
    """
    Parse a raw User-Agent string into structured components.

    Returns:
        {
            "os":          "Windows 10",
            "browser":     "Chrome 120.0.0",
            "device_type": "PC" | "Mobile" | "Tablet" | "Bot" | "Other",
            "raw":         "<original UA string>"
        }
    """
    if not ua_string:
        return {"os": "Unknown", "browser": "Unknown", "device_type": "Other", "raw": ""}

    ua = ua_parse(ua_string)

    if ua.is_bot:
        device_type = "Bot"
    elif ua.is_mobile:
        device_type = "Mobile"
    elif ua.is_tablet:
        device_type = "Tablet"
    elif ua.is_pc:
        device_type = "PC"
    else:
        device_type = "Other"

    os_str = ua.os.family
    if ua.os.version_string:
        os_str += f" {ua.os.version_string}"

    browser_str = ua.browser.family
    if ua.browser.version_string:
        browser_str += f" {ua.browser.version_string}"

    return {
        "os": os_str,
        "browser": browser_str,
        "device_type": device_type,
        "raw": ua_string[:512],  # cap at 512 chars to avoid absurdly long UAs
    }


def fingerprint_device(ip_address: str, ua_string: str) -> str:
    """
    Generate a stable 64-char hex fingerprint for a device + network pair.

    Uses the IP subnet (first 3 octets) so the fingerprint survives
    DHCP lease renewals within the same local network.
    """
    # Extract subnet — gracefully handle IPv6 or malformed IPs
    parts = ip_address.split(".")
    subnet = ".".join(parts[:3]) if len(parts) == 4 else ip_address

    raw = f"{subnet}|{ua_string}"
    return hashlib.sha256(raw.encode()).hexdigest()
