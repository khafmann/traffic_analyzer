from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

WARN_EXPIRY_DAYS = 30
WEAK_CIPHER_KEYWORDS = ("null", "rc4", "_des_", "3des", "export", "_anon_")


class Protocol(str, Enum):
    TLS = "TLS"
    QUIC = "QUIC"
    UNKNOWN = "UNKNOWN"


class TLSVersion(str, Enum):
    SSL_3_0 = "SSL 3.0"
    TLS_1_0 = "TLS 1.0"
    TLS_1_1 = "TLS 1.1"
    TLS_1_2 = "TLS 1.2"
    TLS_1_3 = "TLS 1.3"
    UNKNOWN = "Unknown"


INSECURE_VERSIONS = {TLSVersion.SSL_3_0, TLSVersion.TLS_1_0, TLSVersion.TLS_1_1}

VERSION_MAP = {
    0x0300: TLSVersion.SSL_3_0,
    0x0301: TLSVersion.TLS_1_0,
    0x0302: TLSVersion.TLS_1_1,
    0x0303: TLSVersion.TLS_1_2,
    0x0304: TLSVersion.TLS_1_3,
}

# TLS record content types
TLS_HANDSHAKE = 0x16
TLS_CHANGE_CIPHER_SPEC = 0x14
TLS_ALERT = 0x15
TLS_APPLICATION_DATA = 0x17

# TLS handshake types
HS_CLIENT_HELLO = 0x01
HS_SERVER_HELLO = 0x02
HS_CERTIFICATE = 0x0B
HS_SERVER_HELLO_DONE = 0x0E
HS_FINISHED = 0x14

# TLS extension types
EXT_SNI = 0x0000
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B

CIPHER_SUITE_NAMES = {
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}


@dataclass
class CertInfo:
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None
    not_after: Optional[datetime] = None
    san: list[str] = field(default_factory=list)
    sig_algorithm: str = ""
    is_self_signed: bool = False
    is_expired: bool = False
    is_expiring_soon: bool = False
    is_weak_sig: bool = False


@dataclass
class TLSSession:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    transport: str = "TCP"
    protocol: Protocol = Protocol.TLS
    tls_version: TLSVersion = TLSVersion.UNKNOWN
    negotiated_version: TLSVersion = TLSVersion.UNKNOWN
    sni: Optional[str] = None
    alpn: Optional[list[str]] = None
    cipher_suite: Optional[str] = None
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    client_hello_seen: bool = False
    server_hello_seen: bool = False
    packet_count: int = 0
    cert_der: Optional[bytes] = field(default=None, repr=False)
    cert_info: Optional[CertInfo] = None
    security_issues: list[str] = field(default_factory=list)
    warn_logged: bool = False

    @property
    def flow_key(self) -> tuple:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port)

    @property
    def display_version(self) -> str:
        if self.negotiated_version != TLSVersion.UNKNOWN:
            return self.negotiated_version.value
        return self.tls_version.value

    def __str__(self) -> str:
        sni_str = f" [{self.sni}]" if self.sni else ""
        alpn_str = f" ALPN={','.join(self.alpn)}" if self.alpn else ""
        cipher_str = f" {self.cipher_suite}" if self.cipher_suite else ""
        return (
            f"{self.protocol.value} {self.display_version}{sni_str}"
            f" {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"
            f"{alpn_str}{cipher_str}"
        )


@dataclass
class QUICSession:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    transport: str = "UDP"
    protocol: Protocol = Protocol.QUIC
    version: Optional[int] = None
    sni: Optional[str] = None
    alpn: Optional[list[str]] = None
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    packet_count: int = 0

    KNOWN_VERSIONS = {
        0x00000001: "QUIC v1 (RFC 9000)",
        0x6B3343CF: "QUIC draft-29",
        0xFF00001D: "QUIC draft-29 (alt)",
        0x1: "QUIC v1",
    }

    @property
    def flow_key(self) -> tuple:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port)

    @property
    def version_str(self) -> str:
        if self.version is None:
            return "Unknown"
        return self.KNOWN_VERSIONS.get(self.version, f"0x{self.version:08X}")

    def __str__(self) -> str:
        sni_str = f" [{self.sni}]" if self.sni else ""
        alpn_str = f" ALPN={','.join(self.alpn)}" if self.alpn else ""
        return (
            f"QUIC {self.version_str}{sni_str}"
            f" {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"
            f"{alpn_str}"
        )
