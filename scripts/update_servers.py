
#!/usr/bin/env python3

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import re
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


# ============================================================
# CONFIG
# ============================================================

ROOT = Path(__file__).resolve().parent.parent

SERVER_DIR = ROOT / "servers"
OVPN_DIR = SERVER_DIR / "ovpn"
JSON_FILE = SERVER_DIR / "servers.json"

TIMEOUT = int(
    os.environ.get(
        "VPN_FETCH_TIMEOUT",
        "30",
    )
)

MAX_SERVERS = int(
    os.environ.get(
        "VPN_MAX_SERVERS",
        "0",
    )
)

MIN_SCORE = int(
    os.environ.get(
        "VPN_MIN_SCORE",
        "0",
    )
)

MAX_PING = int(
    os.environ.get(
        "VPN_MAX_PING",
        "0",
    )
)

USER_AGENT = (
    "Mozilla/5.0 "
    "(Linux; Android 15) "
    "VPNGateServerUpdater/1.0"
)


# ============================================================
# VPN GATE SOURCES
# ============================================================

SOURCES = [
    {
        "name": "official-https",
        "url": "https://www.vpngate.net/api/iphone/",
        "priority": 0,
    },
    {
        "name": "official-http",
        "url": "http://www.vpngate.net/api/iphone/",
        "priority": 1,
    },
    {
        "name": "mirror-https",
        "url": (
            "https://raw.githubusercontent.com/"
            "baoweise-bot/aimili-vpngate/"
            "mirror/vpngate.csv"
        ),
        "priority": 2,
    },
    {
        "name": "mirror-http",
        "url": (
            "http://raw.githubusercontent.com/"
            "baoweise-bot/aimili-vpngate/"
            "mirror/vpngate.csv"
        ),
        "priority": 3,
    },
]


# ============================================================
# HELPERS
# ============================================================

def clean(value: Any) -> str:
    if value is None:
        return ""

    return str(value).strip()


def to_int(
    value: Any,
    default: int = 0,
) -> int:

    try:
        text = clean(value)

        if not text:
            return default

        return int(
            float(
                text.replace(",", "")
            )
        )

    except (
        ValueError,
        TypeError,
    ):
        return default


def safe_filename(value: str) -> str:

    value = clean(value)

    value = re.sub(
        r"[^A-Za-z0-9._-]+",
        "-",
        value,
    )

    value = value.strip("-")

    return value[:100] or "server"


def utc_now() -> str:

    from datetime import (
        datetime,
        timezone,
    )

    return (
        datetime.now(
            timezone.utc
        )
        .isoformat()
        .replace(
            "+00:00",
            "Z",
        )
    )


# ============================================================
# HTTP FETCH
# ============================================================

def fetch_url(
    url: str,
) -> bytes:

    print(
        f"[FETCH] {url}"
    )

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": (
                "text/csv,text/plain,*/*"
            ),
            "Cache-Control": "no-cache",
        },
    )

    context = None

    # Normal certificate verification.
    if url.startswith("https://"):
        context = ssl.create_default_context()

    try:

        with urllib.request.urlopen(
            request,
            timeout=TIMEOUT,
            context=context,
        ) as response:

            data = response.read()

            if not data:
                raise RuntimeError(
                    "empty response"
                )

            print(
                f"[FETCH OK] {len(data)} bytes"
            )

            return data

    except Exception as exc:

        raise RuntimeError(
            f"{type(exc).__name__}: {exc}"
        ) from exc


# ============================================================
# VPN GATE CSV PARSER
# ============================================================

def parse_csv(
    data: bytes,
) -> list[dict[str, str]]:

    text = data.decode(
        "utf-8",
        errors="replace",
    )

    text = text.replace(
        "\r\n",
        "\n",
    )

    text = text.replace(
        "\r",
        "\n",
    )

    lines = text.splitlines()

    header_index = None

    for index, line in enumerate(lines):

        line = line.strip()

        normalized = line

        if normalized.startswith("#"):
            normalized = normalized[1:]

        normalized = normalized.strip()

        if normalized.startswith(
            "HostName,"
        ):

            header_index = index
            break

    if header_index is None:

        preview = "\n".join(
            lines[:10]
        )

        raise RuntimeError(
            "VPN Gate CSV header not found.\n"
            f"Response preview:\n{preview}"
        )

    csv_text = "\n".join(
        lines[header_index:]
    )

    reader = csv.DictReader(
        io.StringIO(csv_text)
    )

    rows = []

    for row in reader:

        if not row:
            continue

        normalized_row = {}

        for key, value in row.items():

            if key is None:
                continue

            key = key.strip()

            if key.startswith("#"):
                key = key[1:]

            key = key.strip()

            normalized_row[key] = clean(
                value
            )

        if normalized_row:
            rows.append(
                normalized_row
            )

    return rows


# ============================================================
# BASE64 OPENVPN CONFIG
# ============================================================

def decode_openvpn(
    encoded: str,
) -> str:

    encoded = clean(encoded)

    if not encoded:
        raise ValueError(
            "OpenVPN_ConfigData_Base64 is empty"
        )

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
            f"Base64 decode failed: {exc}"
        ) from exc

    if not raw:

        raise ValueError(
            "Decoded OpenVPN config is empty"
        )

    config = raw.decode(
        "utf-8",
        errors="replace",
    )

    if not config.strip():

        raise ValueError(
            "Decoded OpenVPN config is blank"
        )

    return config


# ============================================================
# OPENVPN PARSING
# ============================================================

def get_remotes(
    config: str,
) -> list[dict[str, Any]]:

    result = []

    for raw in config.splitlines():

        line = raw.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        if line.startswith(";"):
            continue

        parts = line.split()

        if len(parts) < 2:
            continue

        if parts[0].lower() != "remote":
            continue

        host = parts[1]

        port = None

        if len(parts) >= 3:

            try:
                port = int(
                    parts[2]
                )
            except ValueError:
                pass

        protocol = None

        if len(parts) >= 4:

            protocol = (
                parts[3]
                .strip()
                .lower()
            )

        result.append(
            {
                "host": host,
                "port": port,
                "protocol": protocol,
            }
        )

    return result


def get_proto(
    config: str,
) -> str | None:

    for raw in config.splitlines():

        line = raw.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        if line.startswith(";"):
            continue

        parts = line.split()

        if len(parts) >= 2:

            if parts[0].lower() == "proto":

                return parts[1].lower()

    return None


def is_valid_openvpn(
    config: str,
) -> bool:

    lower = config.lower()

    return (
        re.search(
            r"(?m)^\s*client\s*$",
            lower,
        )
        is not None
        and re.search(
            r"(?m)^\s*remote\s+",
            lower,
        )
        is not None
    )


# ============================================================
# SERVER ID
# ============================================================

def server_id(
    hostname: str,
    ip: str,
    country: str,
) -> str:

    raw = "|".join(
        [
            hostname,
            ip,
            country,
        ]
    )

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()[:16]


# ============================================================
# NORMALIZE SERVER
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

    encoded = clean(
        row.get(
            "OpenVPN_ConfigData_Base64"
        )
    )

    if not encoded:
        return None

    try:

        config = decode_openvpn(
            encoded
        )

    except Exception as exc:

        print(
            "[SKIP] Base64:",
            hostname or ip,
            exc,
        )

        return None

    if not is_valid_openvpn(
        config
    ):

        print(
            "[SKIP] Invalid OpenVPN:",
            hostname or ip,
        )

        return None

    remotes = get_remotes(
        config
    )

    if not remotes:

        print(
            "[SKIP] No remote:",
            hostname or ip,
        )

        return None

    score = to_int(
        row.get("Score")
    )

    ping = to_int(
        row.get("Ping")
    )

    speed = to_int(
        row.get("Speed")
    )

    uptime = to_int(
        row.get("Uptime")
    )

    sessions = to_int(
        row.get(
            "NumVpnSessions"
        )
    )

    total_users = to_int(
        row.get(
            "TotalUsers"
        )
    )

    total_traffic = to_int(
        row.get(
            "TotalTraffic"
        )
    )

    if (
        MIN_SCORE > 0
        and score < MIN_SCORE
    ):
        return None

    if (
        MAX_PING > 0
        and (
            ping <= 0
            or ping > MAX_PING
        )
    ):
        return None

    country = clean(
        row.get("CountryLong")
    )

    country_code = clean(
        row.get("CountryShort")
    ).upper()

    protocol = get_proto(
        config
    )

    return {
        "id": server_id(
            hostname,
            ip,
            country_code,
        ),

        "name": (
            hostname
            or ip
        ),

        "hostname": hostname,
        "ip": ip,

        "country": country,
        "countryCode": country_code,

        "score": score,

        "pingMs": (
            ping
            if ping > 0
            else None
        ),

        "speedMbps": (
            round(
                speed / 1_000_000,
                3,
            )
            if speed > 0
            else 0
        ),

        "sessions": sessions,
        "uptimeMinutes": uptime,
        "totalUsers": total_users,
        "totalTrafficBytes": total_traffic,

        "operator": clean(
            row.get("Operator")
        ),

        "logType": clean(
            row.get("LogType")
        ),

        "message": clean(
            row.get("Message")
        ),

        "source": source["name"],

        "remotes": remotes,

        "protocol": protocol,

        "username": "vpn",
        "password": "vpn",

        "_ovpn": config,
    }


# ============================================================
# FETCH SOURCE
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

    print(
        f"[CSV] {source['name']}: "
        f"{len(rows)} rows"
    )

    servers = []

    for row in rows:

        try:

            server = normalize_server(
                row,
                source,
            )

            if server is not None:
                servers.append(
                    server
                )

        except Exception as exc:

            print(
                "[SKIP]",
                row.get("HostName")
                or row.get("IP")
                or "unknown",
                exc,
            )

    return servers


# ============================================================
# FETCH ALL
# ============================================================

def fetch_all() -> list[dict[str, Any]]:

    all_servers = []

    successful_sources = 0

    for source in SOURCES:

        try:

            servers = fetch_source(
                source
            )

            print(
                f"[OK] {source['name']}: "
                f"{len(servers)} OpenVPN servers"
            )

            all_servers.extend(
                servers
            )

            successful_sources += 1

        except Exception as exc:

            print(
                f"[FAIL] {source['name']}: "
                f"{exc}"
            )

    if successful_sources == 0:

        raise RuntimeError(
            "ALL VPN Gate sources failed"
        )

    if not all_servers:

        raise RuntimeError(
            "Sources succeeded but "
            "no OpenVPN servers were found"
        )

    return all_servers


# ============================================================
# DEDUPLICATE
# ============================================================

def deduplicate(
    servers: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    result = {}

    for server in servers:

        ip = clean(
            server.get("ip")
        )

        hostname = clean(
            server.get("hostname")
        )

        if ip:
            key = "ip:" + ip
        elif hostname:
            key = (
                "host:"
                + hostname.lower()
            )
        else:
            continue

        old = result.get(key)

        if old is None:

            result[key] = server
            continue

        old_priority = next(
            (
                x["priority"]
                for x in SOURCES
                if x["name"]
                == old["source"]
            ),
            999,
        )

        new_priority = next(
            (
                x["priority"]
                for x in SOURCES
                if x["name"]
                == server["source"]
            ),
            999,
        )

        if new_priority < old_priority:

            result[key] = server
            continue

        if new_priority > old_priority:
            continue

        old_score = (
            old.get("score")
            or 0
        )

        new_score = (
            server.get("score")
            or 0
        )

        if new_score > old_score:

            result[key] = server
            continue

        if new_score < old_score:
            continue

        old_ping = (
            old.get("pingMs")
            or 999999
        )

        new_ping = (
            server.get("pingMs")
            or 999999
        )

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
        key=lambda s: (
            -(s.get("score") or 0),
            s.get("pingMs")
            or 999999,
            -(s.get("speedMbps") or 0),
        ),
    )


# ============================================================
# OVPN FILENAME
# ============================================================

def ovpn_filename(
    server: dict[str, Any],
    index: int,
) -> str:

    country = safe_filename(
        server.get(
            "countryCode"
        )
        or "XX"
    )

    hostname = safe_filename(
        server.get(
            "hostname"
        )
        or server.get(
            "ip"
        )
        or "server"
    )

    return (
        f"{index:04d}-"
        f"{country}-"
        f"{hostname}.ovpn"
    )


# ============================================================
# WRITE OVPN
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

    config = config.rstrip()

    # VPN Gate normally already supplies the
    # complete OpenVPN profile.
    #
    # Only add credentials if the profile does
    # not already contain auth-user-pass.

    if not re.search(
        r"(?im)^\s*auth-user-pass\b",
        config,
    ):

        config += (
            "\n\n"
            "<auth-user-pass>\n"
            "vpn\n"
            "vpn\n"
            "</auth-user-pass>\n"
        )

    path.write_text(
        config.rstrip()
        + "\n",
        encoding="utf-8",
    )


# ============================================================
# GENERATE OUTPUTS
# ============================================================

def generate_outputs(
    servers: list[dict[str, Any]],
) -> None:

    SERVER_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp_root = Path(
        tempfile.mkdtemp(
            prefix=".vpn-update-",
            dir=str(SERVER_DIR),
        )
    )

    temp_ovpn = (
        temp_root / "ovpn"
    )

    temp_ovpn.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:

        public_servers = []

        for index, server in enumerate(
            servers,
            start=1,
        ):

            config = server.get(
                "_ovpn"
            )

            if not config:
                raise RuntimeError(
                    "Missing OVPN config"
                )

            filename = ovpn_filename(
                server,
                index,
            )

            file_path = (
                temp_ovpn
                / filename
            )

            write_ovpn(
                file_path,
                config,
            )

            if not file_path.exists():

                raise RuntimeError(
                    f"OVPN was not created: "
                    f"{filename}"
                )

            if file_path.stat().st_size < 100:

                raise RuntimeError(
                    f"OVPN file too small: "
                    f"{filename}"
                )

            configs = []

            for remote in server.get(
                "remotes",
                [],
            ):

                configs.append(
                    {
                        "file": (
                            "ovpn/"
                            + filename
                        ),
                        "host": remote.get(
                            "host"
                        ),
                        "port": remote.get(
                            "port"
                        ),
                        "protocol": (
                            remote.get(
                                "protocol"
                            )
                            or server.get(
                                "protocol"
                            )
                        ),
                    }
                )

            public = {}

            for key, value in server.items():

                if key == "_ovpn":
                    continue

                public[key] = value

            public[
                "configs"
            ] = configs

            public_servers.append(
                public
            )

        # ----------------------------------------------------
        # Create JSON in temporary location
        # ----------------------------------------------------

        payload = {
            "schemaVersion": 1,

            "generatedAt": utc_now(),

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

        temp_json = (
            temp_root
            / "servers.json"
        )

        with temp_json.open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as f:

            json.dump(
                payload,
                f,
                ensure_ascii=False,
                indent=2,
            )

            f.write("\n")

        # ----------------------------------------------------
        # Validate JSON BEFORE publishing
        # ----------------------------------------------------

        with temp_json.open(
            "r",
            encoding="utf-8",
        ) as f:

            json.load(f)

        print(
            f"[JSON OK] "
            f"{len(public_servers)} servers"
        )

        # ----------------------------------------------------
        # Publish atomically
        # ----------------------------------------------------

        new_ovpn = (
            SERVER_DIR
            / ".ovpn.new"
        )

        new_json = (
            SERVER_DIR
            / "servers.json.new"
        )

        if new_ovpn.exists():

            import shutil

            shutil.rmtree(
                new_ovpn
            )

        import shutil

        shutil.copytree(
            temp_ovpn,
            new_ovpn,
        )

        shutil.copy2(
            temp_json,
            new_json,
        )

        # Final checks.

        if not new_json.exists():
            raise RuntimeError(
                "servers.json.new missing"
            )

        if new_json.stat().st_size == 0:
            raise RuntimeError(
                "servers.json.new is empty"
            )

        with new_json.open(
            "r",
            encoding="utf-8",
        ) as f:

            json.load(f)

        # Replace old data only AFTER all
        # generation and validation succeeded.

        if OVPN_DIR.exists():

            shutil.rmtree(
                OVPN_DIR
            )

        new_ovpn.rename(
            OVPN_DIR
        )

        if JSON_FILE.exists():

            JSON_FILE.unlink()

        new_json.rename(
            JSON_FILE
        )

        print(
            "[PUBLISH OK]"
        )

    finally:

        import shutil

        shutil.rmtree(
            temp_root,
            ignore_errors=True,
        )


# ============================================================
# MAIN
# ============================================================

def main() -> int:

    print("=" * 60)
    print("VPN GATE SERVER UPDATER")
    print("=" * 60)

    print(
        "Root:",
        ROOT,
    )

    print(
        "Output:",
        SERVER_DIR,
    )

    print(
        "Sources:",
        len(SOURCES),
    )

    print("")

    # --------------------------------------------------------
    # Fetch
    # --------------------------------------------------------

    servers = fetch_all()

    print("")
    print(
        "[TOTAL]",
        len(servers),
        "servers collected",
    )

    # --------------------------------------------------------
    # Deduplicate
    # --------------------------------------------------------

    servers = deduplicate(
        servers
    )

    print(
        "[DEDUPE]",
        len(servers),
        "servers",
    )

    if not servers:

        raise RuntimeError(
            "No servers after deduplication"
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
            "[LIMIT]",
            len(servers),
        )

    # --------------------------------------------------------
    # Generate
    # --------------------------------------------------------

    print("")
    print(
        "[GENERATE] Creating OVPN files..."
    )

    generate_outputs(
        servers
    )

    print("")
    print("=" * 60)
    print(
        "[SUCCESS]",
        len(servers),
        "servers generated",
    )
    print(
        "JSON:",
        JSON_FILE,
    )
    print(
        "OVPN:",
        OVPN_DIR,
    )
    print("=" * 60)

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
            "\n[ERROR]",
            type(exc).__name__,
            str(exc),
            file=sys.stderr,
        )

        sys.exit(1)
