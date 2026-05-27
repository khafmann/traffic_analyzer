import threading
from typing import Optional

from scapy.all import DNS, DNSRR, DNSQR, IP, IPv6, UDP


class DNSCache:

    def __init__(self):
        self._map: dict[str, str] = {}
        self._lock = threading.Lock()

    def process_packet(self, pkt) -> None:
        if not pkt.haslayer(DNS):
            return
        dns = pkt[DNS]
        # Only DNS responses with answers
        if dns.qr != 1 or dns.ancount == 0:
            return

        # Extract queried name from question section
        if not pkt.haslayer(DNSQR):
            return
        qname = pkt[DNSQR].qname
        if isinstance(qname, bytes):
            qname = qname.decode("ascii", errors="replace").rstrip(".")

        rr = dns.an
        ips: list[str] = []
        while rr and rr != 0:
            if rr.type in (1, 28):  # A=1, AAAA=28
                rdata = rr.rdata
                if isinstance(rdata, bytes):
                    try:
                        import socket
                        if rr.type == 1:
                            rdata = socket.inet_ntop(socket.AF_INET, rdata)
                        else:
                            rdata = socket.inet_ntop(socket.AF_INET6, rdata)
                    except Exception:
                        rr = rr.payload if hasattr(rr, "payload") else None
                        continue
                ips.append(str(rdata))
            rr = rr.payload if hasattr(rr, "payload") else None

        if ips and qname:
            with self._lock:
                for ip in ips:
                    # Keep the most specific name (don't overwrite with a CDN alias)
                    if ip not in self._map:
                        self._map[ip] = qname

    def lookup(self, ip: str) -> Optional[str]:
        with self._lock:
            return self._map.get(ip)
