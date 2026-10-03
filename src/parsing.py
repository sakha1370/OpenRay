"""Legacy parser names; all connection parsing uses openray.domain."""

import base64
import ipaddress
import json
import re
from urllib.parse import quote
from openray.domain import SCHEMES, b64decode, extract_uris, parse_uri


def parse_source_line(line):
    url, sep, flag = line.rpartition(",")
    if sep and flag.strip().lower() in {"true", "false", "1", "0", "base64"}:
        return url.strip(), {"base64": flag.strip().lower() in {"true", "1", "base64"}}
    return line.strip(), {"base64": False}


def maybe_decode_subscription(content, hinted_base64=False):
    if "://" in content and not hinted_base64:
        return content
    for _ in range(2):
        try:
            content = b64decode("".join(content.split())).decode("utf-8")
        except (ValueError, UnicodeError):
            break
        if "://" in content:
            break
    return content


def extract_host(uri):
    try:
        return parse_uri(uri).server
    except (ValueError, UnicodeError):
        return None


def extract_port(uri):
    try:
        return parse_uri(uri).port
    except (ValueError, UnicodeError):
        return None


def is_ip_address(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _set_remark(uri, remark):
    p = parse_uri(uri)
    if p.scheme == "vmess":
        data = json.loads(b64decode(uri.split("://", 1)[1].split("#", 1)[0]))
        data["ps"] = remark
        return "vmess://" + base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode()
    if p.scheme == "ssr":
        body = b64decode(uri.split("://", 1)[1]).decode()
        from urllib.parse import parse_qsl, urlencode

        connection, _, query = body.partition("/?")
        pairs = [(k, v) for k, v in parse_qsl(query) if k != "remarks"]
        pairs.append(("remarks", base64.urlsafe_b64encode(remark.encode()).decode().rstrip("=")))
        return "ssr://" + base64.urlsafe_b64encode(
            (connection + "/?" + urlencode(pairs)).encode()
        ).decode().rstrip("=")
    return uri.split("#", 1)[0] + "#" + quote(remark)


def _extract_our_cc_and_num_from_uri(uri):
    try:
        m = re.search(r"\b([A-Z]{2})-(\d+)", parse_uri(uri).remark)
        return (m[1], int(m[2])) if m else None
    except ValueError:
        return None


host_from_vmess = host_from_ss = host_from_ssr = host_from_generic = extract_host
port_from_vmess = port_from_ss = port_from_ssr = port_from_generic = extract_port
