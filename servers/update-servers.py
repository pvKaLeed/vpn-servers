#!/usr/bin/env python3

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import re
import shutil
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parent.parent

SERVER_DIR = ROOT / "servers"
OVPN_DIR = SERVER_DIR / "ovpn"
JSON_FILE = SERVER_DIR / "servers.json"

# ============================================================
# CONFIG
# ============================================================

TIMEOUT = int(os.getenv("VPN_FETCH_TIMEOUT", "30"))

# 0 = keep every valid OpenVPN server
MAX_SERVERS = int(os.getenv("VPN_MAX_SERVERS", "0"))

# Minimum score. 0 = no score filter.
MIN_SCORE = int(os.getenv("VPN_MIN_SCORE", "0"))

# Maximum ping in milliseconds.
# 0 = no ping filter.
MAX_PING = int(os.getenv("VPN_MAX_PING", "0"))

# User-Agent
USER_AGENT = (
    "Mozilla/5.0 "
    "(Linux; Android 15) "
    "VPNServerUpdater/2.0"
)

# ============================================================
# DATA SOURCES
# ============================================================
#
# Priority:
#
# 0 = official HTTPS
# 1 = official HTTP
# 2 = mirror HTTPS
# 3 = mirror HTTP
#
# We FETCH ALL sources.
# If the same server exists in multiple sources,
# the higher-priority source wins.
#
# ============================================================

SOURCES = [
    {
        "name": "vpngate-official-https",
        "url": "https://www.vpngate.net/api/iphone/",
        "priority": 0,
    },
    {
        "name": "vpngate-official-http",
        "url": "http://www.vpngate.net/api/iphone/",
        "priority": 1,
    },
    {
        "name": "vpngate-mirror-https",
        "url": (
            "https://raw.githubusercontent.com/"
            "baoweise-bot/aimili-vpngate/"
            "mirror/vpngate.csv"
        ),
        "priority": 2,
    },
    {
        "name": "vpngate-mirror-http",
        "url": (
            "http://raw.githubusercontent.com/"
            "baoweise-bot/aimili-vpngate/"
            "mirror/vpngate.csv"
        ),
        "priority": 3,
    },
]


# ============================================================
# TIME
# ============================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


# ============================================================
# INTEGER / FLOAT HELPERS
# ============================================================

def to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default

        text = str(value).strip()

        if not text:
            return default

        return int(float(text))

    except (ValueError, TypeError):
        return default


def to_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default

        text = str(value).strip()

        if not text:
            return default

        return float(text)

    except (ValueError, TypeError):
        return default


# ============================================================
# STRING HELPERS
# ============================================================

def clean(value: Any) -> str:
    if value is None:
        return ""

    return str(value).strip()


def safe_filename(value: str) -> str:
    value = clean(value).lower()

    value = re.sub(
        r"[^a-zA-Z0-9._-]+",
        "-",
        value,
    )

    value = value.strip("-")

    if not value:
        value = "server"

    return value[:100]


# ============================================================
# HTTP
# ============================================================

def fetch_url(url: str) -> bytes:
    print(f"[FETCH] {url}")

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/plain,text/csv,*/*",
            "Cache-Control": "no-cache",
        },
    )

    # Normal verified HTTPS request.
    with urllib.request.urlopen(
        request,
        timeout=TIMEOUT,
    ) as response:

        data = response.read()

        if not data:
            raise RuntimeError("empty response")

        return data


# ============================================================
# CSV PARSER
# ============================================================

def parse_csv(data: bytes) -> list[dict[str, str]]:
    """
    VPN Gate API response starts with:

        *vpn_servers
        #HostName,IP,...

    The mirror may contain the same format.

    We locate the actual HostName header instead of assuming
    a fixed number of lines.
    """

    text = data.decode(
        "utf-8",
        errors="replace",
    )

    text = text.replace("\r\n", "\n")
    text = text.replace("\r", "\n")

    lines = text.splitlines()

    header_index = -1

    for index, line in enumerate(lines):

        normalized = line.lstrip("#").strip()

        if normalized.startswith(
            "HostName,"
        ):
            header_index = index
            break

    if header_index < 0:
        raise RuntimeError(
            "VPN Gate CSV header not found"
        )

    csv_text = "\n".join(
        lines[header_index:]
    )

    reader = csv.DictReader(
        io.StringIO(csv_text)
    )

    rows: list[dict[str, str]] = []

    for row in reader:

        if not row:
            continue

        normalized_row: dict[str, str] = {}

        for key, value in row.items():

            if key is None:
                continue

            key = key.lstrip("#").strip()

            normalized_row[key] = (
                clean(value)
            )

        rows.append(
            normalized_row
        )

    return rows


# ============================================================
# BASE64 OPENVPN CONFIG
# ============================================================

def decode_openvpn_config(
    encoded: str,
) -> str:

    encoded = clean(encoded)

    if not encoded:
        raise ValueError(
            "OpenVPN_ConfigData_Base64 is empty"
        )

    # Remove accidental whitespace/newlines.
    encoded = re.sub(
        r"\s+",
        "",
        encoded,
    )

    try:
        raw = base64.b64decode(
            encoded,
            validate=False,
        )

    except Exception as exc:
        raise ValueError(
            f"Invalid OpenVPN Base64: {exc}"
        ) from exc

    if not raw:
        raise ValueError(
            "Decoded OpenVPN config is empty"
        )

    return raw.decode(
        "utf-8",
        errors="replace",
    )


# ============================================================
# OPENVPN CONFIG INFORMATION
# ============================================================

def parse_remote_lines(
    config: str,
) -> list[dict[str, Any]]:

    remotes: list[dict[str, Any]] = []

    for raw_line in config.splitlines():

        line = raw_line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        if line.startswith(";"):
            continue

        parts = line.split()

        if not parts:
            continue

        if parts[0].lower() != "remote":
            continue

        if len(parts) < 2:
            continue

        host = parts[1]

        port = (
            to_int(parts[2])
            if len(parts) >= 3
            else None
        )

        protocol = None

        if len(parts) >= 4:
            protocol = parts[3].lower()

        remotes.append(
            {
                "host": host,
                "port": port,
                "protocol": protocol,
            }
        )

    return remotes


def detect_protocol(
    config: str,
) -> str | None:

    for raw_line in config.splitlines():

        line = raw_line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        if line.startswith(";"):
            continue

        parts = line.split()

        if len(parts) < 2:
            continue

        if parts[0].lower() != "proto":
            continue

        return parts[1].lower()

    return None


def config_has_openvpn(config: str) -> bool:
    """
    Basic sanity check.
    """

    lower = config.lower()

    return (
        "client" in lower
        and "remote " in lower
    )


# ============================================================
# SERVER ID
# ============================================================

def make_server_id(
    hostname: str,
    ip: str,
    country: str,
) -> str:

    identity = "|".join(
        [
            hostname,
            ip,
            country,
        ]
    )

    return hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()[:16]


# ============================================================
# SERVER NORMALIZATION
# ============================================================

def normalize_server(
    row: dict[str, str],
    source: dict[str, Any],
) -> dict[str, Any] | None:

    hostname = clean(
        row.get("HostName")
    )

    ip = clean(
        row.get("IP")
    )

    if not hostname and not ip:
        return None

    country_long = clean(
        row.get("CountryLong")
    )

    country_short = clean(
        row.get("CountryShort")
    ).upper()

    score = to_int(
        row.get("Score")
    )

    ping = to_int(
        row.get("Ping")
    )

    speed_raw = to_int(
        row.get("Speed")
    )

    # VPN Gate Speed is generally represented as
    # bits/second in the API.
    speed_mbps = (
        speed_raw / 1_000_000
        if speed_raw > 0
        else 0.0
    )

    sessions = to_int(
        row.get("NumVpnSessions")
    )

    uptime = to_int(
        row.get("Uptime")
    )

    total_users = to_int(
        row.get("TotalUsers")
    )

    total_traffic = to_int(
        row.get("TotalTraffic")
    )

    operator = clean(
        row.get("Operator")
    )

    log_type = clean(
        row.get("LogType")
    )

    message = clean(
        row.get("Message")
    )

    encoded = clean(
        row.get(
            "OpenVPN_ConfigData_Base64"
        )
    )

    if not encoded:
        return None

    # Filters
    if MIN_SCORE > 0 and score < MIN_SCORE:
        return None

    if MAX_PING > 0:

        if ping <= 0 or ping > MAX_PING:
            return None

    # Decode OpenVPN config.
    try:
        config = decode_openvpn_config(
            encoded
        )

    except Exception as exc:

        print(
            "[SKIP] invalid OpenVPN config "
            f"{hostname or ip}: {exc}"
        )

        return None

    if not config_has_openvpn(config):

        print(
            "[SKIP] not an OpenVPN config "
            f"{hostname or ip}"
        )

        return None

    remotes = parse_remote_lines(
        config
    )

    protocol = detect_protocol(
        config
    )

    server_id = make_server_id(
        hostname,
        ip,
        country_short,
    )

    return {
        "id": server_id,
        "name": hostname or ip,
        "hostname": hostname,
        "ip": ip,
        "country": country_long,
        "countryCode": country_short,

        "score": score,
        "pingMs": ping if ping > 0 else None,
        "speedMbps": round(
            speed_mbps,
            3,
        ),

        "sessions": sessions,
        "uptimeMinutes": uptime,
        "totalUsers": total_users,
        "totalTrafficBytes": total_traffic,

        "operator": operator,
        "logType": log_type,
        "message": message,

        "source": source["name"],
        "sourcePriority": source["priority"],

        "protocol": protocol,
        "remotes": remotes,

        # credentials used by VPN Gate
        "username": "vpn",
        "password": "vpn",

        # Raw config is NOT placed in JSON.
        # It is written as .ovpn separately.
        "_ovpn": config,
    }


# ============================================================
# FETCH ONE SOURCE
# ============================================================

def fetch_source(
    source: dict[str, Any],
) -> list[dict[str, Any]]:

    data = fetch_url(
        source["url"]
    )

    rows = parse_csv(
        data
    )

    servers: list[dict[str, Any]] = []

    for row in rows:

        try:

            server = normalize_server(
                row,
                source,
            )

            if server is not None:
                servers.append(server)

        except Exception as exc:

            host = (
                row.get("HostName")
                or row.get("IP")
                or "unknown"
            )

            print(
                f"[SKIP] {host}: {exc}"
            )

    return servers


# ============================================================
# FETCH ALL SOURCES
# ============================================================

def fetch_all_sources() -> list[dict[str, Any]]:

    all_servers: list[dict[str, Any]] = []

    success_count = 0

    for source in SOURCES:

        try:

            servers = fetch_source(
                source
            )

            print(
                f"[OK] {source['name']}: "
                f"{len(servers)} valid servers"
            )

            all_servers.extend(
                servers
            )

            success_count += 1

        except Exception as exc:

            print(
                f"[FAIL] {source['name']}: "
                f"{exc}"
            )

    if success_count == 0:

        raise RuntimeError(
            "ALL VPN Gate sources failed"
        )

    if not all_servers:

        raise RuntimeError(
            "Sources returned zero valid OpenVPN servers"
        )

    return all_servers


# ============================================================
# DEDUPLICATION
# ============================================================

def deduplicate(
    servers: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    """
    Same server may appear in:
      official HTTPS
      official HTTP
      mirror HTTPS
      mirror HTTP

    Keep the highest-priority source.

    If same source contains duplicates,
    prefer better score / lower ping.
    """

    result: dict[str, dict[str, Any]] = {}

    for server in servers:

        ip = server["ip"]
        hostname = server["hostname"]

        # Primary identity.
        if ip:
            key = f"ip:{ip}"
        elif hostname:
            key = f"host:{hostname.lower()}"
        else:
            continue

        old = result.get(key)

        if old is None:

            result[key] = server
            continue

        old_priority = old[
            "sourcePriority"
        ]

        new_priority = server[
            "sourcePriority"
        ]

        # Lower priority number = better source.
        if new_priority < old_priority:

            result[key] = server
            continue

        if new_priority > old_priority:
            continue

        # Same source priority.
        old_score = old.get(
            "score",
            0,
        )

        new_score = server.get(
            "score",
            0,
        )

        if new_score > old_score:

            result[key] = server
            continue

        if new_score < old_score:
            continue

        old_ping = old.get(
            "pingMs"
        ) or 999999

        new_ping = server.get(
            "pingMs"
        ) or 999999

        if new_ping < old_ping:

            result[key] = server

    return list(
        result.values()
    )


# ============================================================
# SORT
# ============================================================

def sort_servers(
    servers: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    return sorted(
        servers,
        key=lambda server: (
            -(server.get("score") or 0),
            server.get("pingMs")
            or 999999,
            -(server.get("speedMbps") or 0),
        ),
    )


# ============================================================
# OVPN FILE NAME
# ============================================================

def make_ovpn_filename(
    server: dict[str, Any],
    index: int,
) -> str:

    country = safe_filename(
        server.get("countryCode")
        or "XX"
    )

    hostname = safe_filename(
        server.get("hostname")
        or server.get("ip")
        or f"server-{index}"
    )

    return (
        f"{index:04d}-"
        f"{country}-"
        f"{hostname}.ovpn"
    )


# ============================================================
# OVPN FILE
# ============================================================

def write_ovpn(
    path: Path,
    config: str,
) -> None:

    config = config.replace(
        "\r\n",
        "\n",
    )

    config = config.replace(
        "\r",
        "\n",
    )

    # VPN Gate OpenVPN configs already contain
    # the necessary certificates/configuration.
    #
    # Do NOT reconstruct the profile manually.
    # The Base64 profile supplied by VPN Gate is
    # the authoritative OpenVPN configuration.
    #
    # We only ensure auth credentials are available
    # through inline auth-user-pass if the profile
    # does not already define auth-user-pass.

    lower = config.lower()

    if "auth-user-pass" not in lower:

        config = (
            config.rstrip()
            + "\n\n"
            + "<auth-user-pass>\n"
            + "vpn\n"
            + "vpn\n"
            + "</auth-user-pass>\n"
        )

    # Modern OpenVPN clients can use these ciphers.
    # Do not add them if the profile already specifies
    # data-ciphers.
    if "data-ciphers" not in lower:

        config = (
            config.rstrip()
            + "\n"
            + "data-ciphers "
            + "AES-256-GCM:"
            + "AES-128-GCM:"
            + "AES-128-CBC:"
            + "CHACHA20-POLY1305\n"
        )

    path.write_text(
        config.rstrip() + "\n",
        encoding="utf-8",
    )


# ============================================================
# GENERATE OVPN + JSON DATA
# ============================================================

def generate_outputs(
    servers: list[dict[str, Any]],
) -> None:

    SERVER_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Use temporary directory first.
    temp_dir = Path(
        tempfile.mkdtemp(
            prefix="ovpn-",
            dir=str(SERVER_DIR),
        )
    )

    try:

        public_servers: list[
            dict[str, Any]
        ] = []

        for index, server in enumerate(
            servers,
            start=1,
        ):

            config = server.pop(
                "_ovpn"
            )

            filename = make_ovpn_filename(
                server,
                index,
            )

            output_path = (
                temp_dir / filename
            )

            write_ovpn(
                output_path,
                config,
            )

            # Re-read generated file to make sure
            # it was actually written.
            if not output_path.exists():

                raise RuntimeError(
                    f"Failed to create {filename}"
                )

            if output_path.stat().st_size < 100:

                raise RuntimeError(
                    f"Generated OVPN is suspiciously small: "
                    f"{filename}"
                )

            remotes = server.get(
                "remotes",
                [],
            )

            configs = [
                {
                    "file": (
                        f"ovpn/{filename}"
                    ),
                    "protocol": (
                        remote.get("protocol")
                        or server.get("protocol")
                    ),
                    "host": remote.get(
                        "host"
                    ),
                    "port": remote.get(
                        "port"
                    ),
                }
                for remote in remotes
            ]

            # If parser did not find a remote,
            # still publish the config.
            if not configs:

                configs = [
                    {
                        "file": (
                            f"ovpn/{filename}"
                        ),
                        "protocol": server.get(
                            "protocol"
                        ),
                        "host": server.get(
                            "hostname"
                        ) or server.get(
                            "ip"
                        ),
                        "port": None,
                    }
                ]

            public_server = {
                key: value
                for key, value in server.items()
                if key not in {
                    "_ovpn",
                    "sourcePriority",
                }
            }

            public_server[
                "configs"
            ] = configs

            public_servers.append(
                public_server
            )

        # Replace old OVPN directory only after
        # every new config was successfully generated.
        backup_dir = (
            SERVER_DIR
            / ".ovpn-old"
        )

        if backup_dir.exists():
            shutil.rmtree(
                backup_dir
            )

        if OVPN_DIR.exists():

            OVPN_DIR.rename(
                backup_dir
            )

        temp_dir.rename(
            OVPN_DIR
        )

        if backup_dir.exists():

            shutil.rmtree(
                backup_dir
            )

        payload = {
            "schemaVersion": 1,
            "generatedAt": utc_iso(),

            "source": {
                "name": "VPN Gate",
                "sources": [
                    {
                        "name": source["name"],
                        "url": source["url"],
                        "priority": source["priority"],
                    }
                    for source in SOURCES
                ],
            },

            "credentials": {
                "username": "vpn",
                "password": "vpn",
            },

            "count": len(
                public_servers
            ),

            "servers": public_servers,
        }

        # Atomic JSON write.
        temp_json = (
            SERVER_DIR
            / "servers.json.tmp"
        )

        temp_json.write_text(
            json.dumps(
                payload,
                ensure_ascii=False,
                indent=2,
            ) + "\n",
            encoding="utf-8",
        )

        # Validate JSON before replacing.
        with temp_json.open(
            "r",
            encoding="utf-8",
        ) as file:

            json.load(file)

        temp_json.replace(
            JSON_FILE
        )

    except Exception:

        if temp_dir.exists():

            shutil.rmtree(
                temp_dir,
                ignore_errors=True,
            )

        raise


# ============================================================
# MAIN
# ============================================================

def main() -> int:

    print("=" * 70)
    print("VPN GATE SERVER UPDATE")
    print("=" * 70)

    print(
        f"[INFO] Root: {ROOT}"
    )

    print(
        f"[INFO] Output: {SERVER_DIR}"
    )

    print(
        f"[INFO] Sources: {len(SOURCES)}"
    )

    print("")

    # --------------------------------------------------------
    # Fetch all available sources
    # --------------------------------------------------------

    servers = fetch_all_sources()

    print("")
    print(
        f"[INFO] Total collected: "
        f"{len(servers)}"
    )

    # --------------------------------------------------------
    # Deduplicate
    # --------------------------------------------------------

    servers = deduplicate(
        servers
    )

    print(
        f"[INFO] After dedupe: "
        f"{len(servers)}"
    )

    if not servers:

        raise RuntimeError(
            "No servers remain after deduplication"
        )

    # --------------------------------------------------------
    # Sort
    # --------------------------------------------------------

    servers = sort_servers(
        servers
    )

    # --------------------------------------------------------
    # Limit
    # --------------------------------------------------------

    if MAX_SERVERS > 0:

        servers = servers[
            :MAX_SERVERS
        ]

        print(
            f"[INFO] Limited to: "
            f"{len(servers)}"
        )

    # --------------------------------------------------------
    # Generate
    # --------------------------------------------------------

    print("")
    print(
        "[INFO] Generating OpenVPN configs..."
    )

    generate_outputs(
        servers
    )

    print("")
    print("=" * 70)
    print(
        f"[SUCCESS] Servers: "
        f"{len(servers)}"
    )

    print(
        f"[SUCCESS] JSON: "
        f"{JSON_FILE}"
    )

    print(
        f"[SUCCESS] OVPN: "
        f"{OVPN_DIR}"
    )

    print("=" * 70)

    return 0


if __name__ == "__main__":

    try:

        sys.exit(
            main()
        )

    except KeyboardInterrupt:

        print(
            "\n[ERROR] Interrupted",
            file=sys.stderr,
        )

        sys.exit(130)

    except Exception as exc:

        print(
            f"\n[ERROR] {exc}",
            file=sys.stderr,
        )

        sys.exit(1)
