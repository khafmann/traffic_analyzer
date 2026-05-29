import logging
import sys
from datetime import datetime, timezone
from typing import Optional, Union

from dns_cache import DNSCache
from models import QUICSession, TLSSession
from resolver import ReverseDNSCache

Session = Union[TLSSession, QUICSession]


def _session_to_record(
    session: Session,
    event: str,
    resolver: Optional[ReverseDNSCache] = None,
    dns_cache: Optional[DNSCache] = None,
) -> dict:
    """Build a structured log record for a session event."""
    def _resolve(ip: str) -> Optional[str]:
        if dns_cache:
            hit = dns_cache.lookup(ip)
            if hit:
                return hit
        return resolver.lookup(ip) if resolver else None

    src_host = _resolve(session.src_ip)
    dst_host = _resolve(session.dst_ip)

    # SNI is the most reliable server name — use it for whichever side is the server
    if isinstance(session, TLSSession) and session.sni:
        if session.dst_port in (443, 8443):
            dst_host = session.sni
        elif session.src_port in (443, 8443):
            src_host = session.sni

    record: dict = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "event": event,
        # 5-tuple
        "src_ip": session.src_ip,
        "dst_ip": session.dst_ip,
        "src_port": session.src_port,
        "dst_port": session.dst_port,
        "transport": session.transport,
        # resolved hostnames (omitted when unknown)
        "src_host": src_host,
        "dst_host": dst_host,
        # protocol info
        "protocol": session.protocol.value,
    }

    if isinstance(session, TLSSession):
        record["version"] = session.display_version
        record["sni"] = session.sni
        record["alpn"] = session.alpn
        record["cipher_suite"] = session.cipher_suite
        if session.security_issues:
            record["security_issues"] = session.security_issues
        if session.cert_info:
            ci = session.cert_info
            record["cert"] = {
                "subject_cn": ci.subject_cn,
                "issuer_cn": ci.issuer_cn,
                "not_after": ci.not_after.isoformat() if ci.not_after else None,
                "sig_algorithm": ci.sig_algorithm,
                "is_self_signed": ci.is_self_signed,
            }
    elif isinstance(session, QUICSession):
        record["version"] = session.version_str
        record["sni"] = session.sni
        record["alpn"] = session.alpn

    # Drop None values to keep records compact
    return {k: v for k, v in record.items() if v is not None}


def _format_console(record: dict) -> str:
    """Human-readable one-liner for console output."""
    ts = record["timestamp"][11:23]  # HH:MM:SS.mmm from ISO string

    src_addr = record.get("src_host") or record["src_ip"]
    dst_addr = record.get("dst_host") or record["dst_ip"]
    src = f"{src_addr}:{record['src_port']}"
    dst = f"{dst_addr}:{record['dst_port']}"

    transport = record["transport"]
    proto = record["protocol"]
    version = record.get("version", "")
    # show sni only when it's not already visible as the dst hostname
    sni_val = record.get("sni")
    sni = f"  sni={sni_val}" if sni_val and sni_val not in (dst_addr, src_addr) else ""
    alpn = f"  alpn={','.join(record['alpn'])}" if record.get("alpn") else ""
    cipher = f"  cipher={record['cipher_suite']}" if record.get("cipher_suite") else ""
    event = record["event"]
    issues = record.get("security_issues", [])
    warn = f"  !! {', '.join(issues)}" if issues else ""

    return f"{ts}  {event:<7}  {transport}/{proto} {version:<8}  {src} -> {dst}{sni}{alpn}{cipher}{warn}"


class SessionLogger:
    """Logs session events to console (human-readable) and optionally to a file (JSON lines)."""

    def __init__(
        self,
        no_color: bool = False,
        resolve_hosts: bool = True,
        dns_cache: Optional[DNSCache] = None,
    ):
        self.no_color = no_color
        self._resolver: Optional[ReverseDNSCache] = ReverseDNSCache() if resolve_hosts else None
        self._dns_cache: Optional[DNSCache] = dns_cache

        logging.basicConfig(
            stream=sys.stderr,
            level=logging.WARNING,
            format="%(levelname)s %(message)s",
        )
        self.log = logging.getLogger("analyzer")

    # ANSI colors
    _RESET = "\033[0m"
    _COLORS = {
        "TLS":   "\033[36m",
        "QUIC":  "\033[35m",
        "NEW":   "\033[32m",
        "HELLO": "\033[33m",
        "SNI":   "\033[33m",
        "WARN":  "\033[1m\033[31m",
        "ts":    "\033[90m",
    }

    def _colorize(self, line: str, record: dict) -> str:
        event = record.get("event", "")
        proto = record.get("protocol", "")
        color = self._COLORS.get(event) or self._COLORS.get(proto, "")
        ts_color = self._COLORS["ts"]
        parts = line.split("  ", 1)
        if len(parts) == 2:
            return f"{ts_color}{parts[0]}{self._RESET}  {color}{parts[1]}{self._RESET}"
        return f"{color}{line}{self._RESET}"

    def log_session(self, session: Session, event: str = "NEW") -> None:
        record = _session_to_record(session, event, self._resolver, self._dns_cache)

        # Console line
        line = _format_console(record)
        if not self.no_color:
            line = self._colorize(line, record)
        print(line)

    def close(self) -> None:
        if self._resolver:
            self._resolver.close()
