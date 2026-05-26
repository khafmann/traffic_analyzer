import json
import logging
import sys
from datetime import datetime, timezone
from typing import IO, Optional, Union

from models import QUICSession, TLSSession

Session = Union[TLSSession, QUICSession]


def _session_to_record(session: Session, event: str) -> dict:
    """Build a structured log record for a session event."""
    record: dict = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "event": event,
        # 5-tuple
        "src_ip": session.src_ip,
        "dst_ip": session.dst_ip,
        "src_port": session.src_port,
        "dst_port": session.dst_port,
        "transport": session.transport,
        # protocol info
        "protocol": session.protocol.value,
    }

    if isinstance(session, TLSSession):
        record["version"] = session.display_version
        record["sni"] = session.sni
        record["alpn"] = session.alpn
        record["cipher_suite"] = session.cipher_suite
    elif isinstance(session, QUICSession):
        record["version"] = session.version_str
        record["sni"] = session.sni
        record["alpn"] = session.alpn

    # Drop None values to keep records compact
    return {k: v for k, v in record.items() if v is not None}


def _format_console(record: dict) -> str:
    """Human-readable one-liner for console output."""
    ts = record["timestamp"][11:23]  # HH:MM:SS.mmm from ISO string
    src = f"{record['src_ip']}:{record['src_port']}"
    dst = f"{record['dst_ip']}:{record['dst_port']}"
    transport = record["transport"]
    proto = record["protocol"]
    version = record.get("version", "")
    sni = f"  sni={record['sni']}" if record.get("sni") else ""
    alpn = f"  alpn={','.join(record['alpn'])}" if record.get("alpn") else ""
    cipher = f"  cipher={record['cipher_suite']}" if record.get("cipher_suite") else ""
    event = record["event"]

    return f"{ts}  {event:<7}  {transport}/{proto} {version:<8}  {src} -> {dst}{sni}{alpn}{cipher}"


class SessionLogger:
    """Logs session events to console (human-readable) and optionally to a file (JSON lines)."""

    def __init__(self, log_file: Optional[str] = None, no_color: bool = False):
        self.no_color = no_color
        self._file: Optional[IO] = None

        if log_file:
            self._file = open(log_file, "a", buffering=1)  # line-buffered

        # Python logger for stderr warnings/errors from the analyzer itself
        logging.basicConfig(
            stream=sys.stderr,
            level=logging.WARNING,
            format="%(levelname)s %(message)s",
        )
        self.log = logging.getLogger("analyzer")

    # ANSI colors
    _RESET = "\033[0m"
    _COLORS = {
        "TLS":  "\033[36m",   # cyan
        "QUIC": "\033[35m",   # magenta
        "NEW":  "\033[32m",   # green
        "HELLO":"\033[33m",   # yellow
        "PKT":  "\033[90m",   # grey
        "ts":   "\033[90m",
    }

    def _colorize(self, line: str, record: dict) -> str:
        proto = record.get("protocol", "")
        event = record.get("event", "")
        proto_color = self._COLORS.get(proto, "")
        event_color = self._COLORS.get(event, proto_color)
        ts_color = self._COLORS["ts"]

        # Color timestamp separately, rest in proto color
        parts = line.split("  ", 1)
        if len(parts) == 2:
            return f"{ts_color}{parts[0]}{self._RESET}  {proto_color}{parts[1]}{self._RESET}"
        return f"{proto_color}{line}{self._RESET}"

    def log_session(self, session: Session, event: str = "NEW") -> None:
        record = _session_to_record(session, event)

        # Console line
        line = _format_console(record)
        if not self.no_color:
            line = self._colorize(line, record)
        print(line)

        # JSON line to file
        if self._file:
            self._file.write(json.dumps(record, ensure_ascii=False) + "\n")

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None
