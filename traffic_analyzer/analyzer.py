import argparse
import signal
import sys
from collections import defaultdict
from datetime import datetime
from typing import Optional, Union

from scapy.all import sniff, IP, IPv6, TCP, UDP, Raw, conf

from cert_analyzer import get_security_issues, parse_cert_der
from dns_cache import DNSCache
from logger import SessionLogger
from models import Protocol, QUICSession, TLSSession
from parser import try_parse_quic, try_parse_tls

# Suppress scapy warnings
conf.verb = 0

_RESET = "\033[0m"
_BOLD  = "\033[1m"
_GREEN = "\033[32m"
_GREY  = "\033[90m"


class TrafficAnalyzer:
    def __init__(
        self,
        interface: str,
        verbose: bool = False,
        no_color: bool = False,
        log_file: Optional[str] = None,
        resolve_hosts: bool = True,
    ):
        self.interface = interface
        self.verbose = verbose
        self.dns_cache = DNSCache()
        self.logger = SessionLogger(
            log_file=log_file,
            no_color=no_color,
            resolve_hosts=resolve_hosts,
            dns_cache=self.dns_cache,
        )
        self.sessions: dict[tuple, Union[TLSSession, QUICSession]] = {}
        self.stats = defaultdict(int)
        self.start_time = datetime.now()

    def _make_flow_key(self, src_ip, dst_ip, src_port, dst_port) -> tuple:
        a = (src_ip, src_port)
        b = (dst_ip, dst_port)
        if a < b:
            return (src_ip, dst_ip, src_port, dst_port)
        return (dst_ip, src_ip, dst_port, src_port)

    def _handle_tls(self, src_ip, dst_ip, src_port, dst_port, payload: bytes):
        flow_key = self._make_flow_key(src_ip, dst_ip, src_port, dst_port)

        is_new = flow_key not in self.sessions
        if is_new:
            session = TLSSession(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
            )
            self.sessions[flow_key] = session
        else:
            session = self.sessions[flow_key]
            if not isinstance(session, TLSSession):
                return

        had_hello = session.client_hello_seen or session.server_hello_seen
        had_sni = session.sni is not None
        found = try_parse_tls(payload, session)

        if not found and is_new:
            del self.sessions[flow_key]
            return

        session.packet_count += 1
        session.last_seen = datetime.now()
        self.stats["tls_sessions"] += 1 if is_new else 0
        self.stats["tls_packets"] += 1

        # Parse certificate if freshly extracted
        if session.cert_der is not None:
            ci = parse_cert_der(session.cert_der)
            session.cert_der = None
            if ci:
                session.cert_info = ci

        # Recompute security issues after any new info
        session.security_issues = get_security_issues(session)

        sni_discovered = not had_sni and session.sni is not None
        warn_needed = bool(session.security_issues) and not session.warn_logged

        if is_new and found:
            self.logger.log_session(session, "NEW")
        elif not had_hello and (session.client_hello_seen or session.server_hello_seen):
            self.logger.log_session(session, "HELLO")
        elif sni_discovered:
            self.logger.log_session(session, "SNI")
        elif self.verbose:
            self.logger.log_session(session, "PKT")

        if warn_needed:
            session.warn_logged = True
            self.logger.log_session(session, "WARN")
            self.stats["warn_sessions"] += 1

    def _handle_quic(self, src_ip, dst_ip, src_port, dst_port, payload: bytes):
        flow_key = self._make_flow_key(src_ip, dst_ip, src_port, dst_port)

        is_new = flow_key not in self.sessions
        if is_new:
            session = QUICSession(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
            )
        else:
            session = self.sessions[flow_key]
            if not isinstance(session, QUICSession):
                return

        found = try_parse_quic(payload, session)
        if not found and is_new:
            return

        if is_new:
            self.sessions[flow_key] = session

        session.packet_count += 1
        session.last_seen = datetime.now()
        self.stats["quic_sessions"] += 1 if is_new else 0
        self.stats["quic_packets"] += 1

        if is_new:
            self.logger.log_session(session, "NEW")
        elif self.verbose:
            self.logger.log_session(session, "PKT")

    def process_packet(self, pkt):
        self.dns_cache.process_packet(pkt)

        if not pkt.haslayer(Raw):
            return

        payload = bytes(pkt[Raw])
        ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip_layer is None:
            return

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port, dst_port = tcp.sport, tcp.dport
            if len(payload) >= 5:
                self._handle_tls(src_ip, dst_ip, src_port, dst_port, payload)

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port, dst_port = udp.sport, udp.dport
            self._handle_quic(src_ip, dst_ip, src_port, dst_port, payload)

    def print_stats(self):
        elapsed = (datetime.now() - self.start_time).total_seconds()
        print(f"\n{_BOLD}=== Statistics ==={_RESET}")
        print(f"  Runtime:        {elapsed:.1f}s")
        print(f"  TLS sessions:   {self.stats['tls_sessions']}")
        print(f"  TLS packets:    {self.stats['tls_packets']}")
        print(f"  QUIC sessions:  {self.stats['quic_sessions']}")
        print(f"  QUIC packets:   {self.stats['quic_packets']}")
        print(f"  Active flows:   {len(self.sessions)}")
        if self.stats["warn_sessions"]:
            print(f"  {_BOLD}\033[31mInsecure:       {self.stats['warn_sessions']}{_RESET}")

    def run(self):
        print(f"{_BOLD}{_GREEN}[*] Listening on {self.interface} — Ctrl+C to stop{_RESET}")
        print(f"{_GREY}[*] Capturing TLS (TCP) and QUIC (UDP) traffic{_RESET}")
        print()

        def sig_handler(sig, frame):
            self.print_stats()
            self.logger.close()
            sys.exit(0)

        signal.signal(signal.SIGINT, sig_handler)

        sniff(
            iface=self.interface,
            filter="tcp or udp",
            prn=self.process_packet,
            store=False,
        )


def main():
    parser = argparse.ArgumentParser(description="Real-time TLS/SSL/QUIC traffic analyzer")
    parser.add_argument("interface", help="Network interface to capture on (e.g. eth0, wlan0)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all packets, not just new sessions")
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    parser.add_argument("--log-file", metavar="PATH", help="Append JSON-lines session log to this file")
    args = parser.parse_args()

    analyzer = TrafficAnalyzer(
        interface=args.interface,
        verbose=args.verbose,
        no_color=args.no_color,
        log_file=args.log_file,
    )
    analyzer.run()


if __name__ == "__main__":
    main()
