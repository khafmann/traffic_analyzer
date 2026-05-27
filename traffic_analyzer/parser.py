import struct

from models import (
    CIPHER_SUITE_NAMES,
    EXT_ALPN,
    EXT_SNI,
    EXT_SUPPORTED_VERSIONS,
    HS_CERTIFICATE,
    HS_CLIENT_HELLO,
    HS_SERVER_HELLO,
    TLS_HANDSHAKE,
    VERSION_MAP,
    TLSVersion,
    QUICSession,
    TLSSession,
)


def parse_tls_extensions(data: bytes, offset: int, length: int) -> dict:
    result = {"sni": None, "alpn": [], "supported_versions": []}
    end = offset + length
    while offset + 4 <= end:
        ext_type = struct.unpack_from("!H", data, offset)[0]
        ext_len = struct.unpack_from("!H", data, offset + 2)[0]
        offset += 4
        ext_data = data[offset : offset + ext_len]

        if ext_type == EXT_SNI and len(ext_data) >= 5:
            # server_name_list_length(2) + name_type(1) + name_length(2) + name
            name_list_len = struct.unpack_from("!H", ext_data, 0)[0]
            if name_list_len >= 3:
                name_type = ext_data[2]
                if name_type == 0:  # host_name
                    name_len = struct.unpack_from("!H", ext_data, 3)[0]
                    result["sni"] = ext_data[5 : 5 + name_len].decode("ascii", errors="replace")

        elif ext_type == EXT_ALPN and len(ext_data) >= 2:
            alpn_list_len = struct.unpack_from("!H", ext_data, 0)[0]
            pos = 2
            while pos < 2 + alpn_list_len and pos < len(ext_data):
                proto_len = ext_data[pos]
                pos += 1
                if pos + proto_len <= len(ext_data):
                    result["alpn"].append(ext_data[pos : pos + proto_len].decode("ascii", errors="replace"))
                    pos += proto_len

        elif ext_type == EXT_SUPPORTED_VERSIONS:
            if len(ext_data) >= 1:
                # In ClientHello: list of versions; in ServerHello: single version
                if ext_data[0] == len(ext_data) - 1:  # ClientHello list
                    list_len = ext_data[0]
                    for i in range(1, 1 + list_len, 2):
                        if i + 1 < len(ext_data):
                            v = struct.unpack_from("!H", ext_data, i)[0]
                            if v in VERSION_MAP:
                                result["supported_versions"].append(VERSION_MAP[v])
                else:  # ServerHello single version
                    if len(ext_data) >= 2:
                        v = struct.unpack_from("!H", ext_data, 0)[0]
                        if v in VERSION_MAP:
                            result["supported_versions"].append(VERSION_MAP[v])

        offset += ext_len
    return result


def parse_client_hello(data: bytes, session: TLSSession) -> bool:
    # data starts at handshake body (after type+length)
    if len(data) < 34:
        return False
    try:
        offset = 0
        # client_version(2) + random(32)
        client_version = struct.unpack_from("!H", data, offset)[0]
        session.tls_version = VERSION_MAP.get(client_version, TLSVersion.UNKNOWN)
        offset += 34  # skip version + random

        # session_id
        sid_len = data[offset]
        offset += 1 + sid_len

        if offset + 2 > len(data):
            return True

        # cipher_suites
        cs_len = struct.unpack_from("!H", data, offset)[0]
        offset += 2 + cs_len

        if offset + 1 > len(data):
            return True

        # compression_methods
        comp_len = data[offset]
        offset += 1 + comp_len

        if offset + 2 > len(data):
            return True

        # extensions
        ext_total_len = struct.unpack_from("!H", data, offset)[0]
        offset += 2
        exts = parse_tls_extensions(data, offset, ext_total_len)
        session.sni = exts["sni"]
        session.alpn = exts["alpn"] or None
        if exts["supported_versions"]:
            session.tls_version = exts["supported_versions"][0]

        session.client_hello_seen = True
        return True
    except (struct.error, IndexError):
        return False


def parse_server_hello(data: bytes, session: TLSSession) -> bool:
    if len(data) < 36:
        return False
    try:
        offset = 0
        server_version = struct.unpack_from("!H", data, offset)[0]
        session.negotiated_version = VERSION_MAP.get(server_version, TLSVersion.UNKNOWN)
        offset += 34  # version + random

        # session_id
        sid_len = data[offset]
        offset += 1 + sid_len

        if offset + 2 > len(data):
            return True

        # cipher_suite
        cs_id = struct.unpack_from("!H", data, offset)[0]
        session.cipher_suite = CIPHER_SUITE_NAMES.get(cs_id, f"0x{cs_id:04X}")
        offset += 2

        # compression_method
        offset += 1

        if offset + 2 > len(data):
            return True

        ext_total_len = struct.unpack_from("!H", data, offset)[0]
        offset += 2
        exts = parse_tls_extensions(data, offset, ext_total_len)
        if exts["supported_versions"]:
            session.negotiated_version = exts["supported_versions"][0]

        session.server_hello_seen = True
        return True
    except (struct.error, IndexError):
        return False


def _extract_first_cert_der(data: bytes, session: TLSSession) -> bytes | None:
    """Extract DER bytes of the first certificate from a Certificate handshake body."""
    try:
        offset = 0
        # TLS 1.3 prepends a 1-byte certificate_request_context_length
        if session.negotiated_version == TLSVersion.TLS_1_3:
            ctx_len = data[offset]
            offset += 1 + ctx_len

        # uint24: total certificate_list length
        if offset + 3 > len(data):
            return None
        offset += 3  # skip list length

        # uint24: first certificate length
        if offset + 3 > len(data):
            return None
        cert_len = struct.unpack_from("!I", b"\x00" + data[offset: offset + 3])[0]
        offset += 3

        if cert_len == 0 or offset + cert_len > len(data):
            return None
        return data[offset: offset + cert_len]
    except (struct.error, IndexError):
        return None


def try_parse_tls(payload: bytes, session: TLSSession) -> bool:
    """Try to parse TLS records from raw TCP payload. Returns True if valid TLS found."""
    if len(payload) < 5:
        return False

    offset = 0
    found = False

    while offset + 5 <= len(payload):
        content_type = payload[offset]
        version = struct.unpack_from("!H", payload, offset + 1)[0]
        record_len = struct.unpack_from("!H", payload, offset + 3)[0]

        # Sanity checks
        if content_type not in (0x14, 0x15, 0x16, 0x17):
            break
        if version not in VERSION_MAP and version not in (0x0301, 0x0302, 0x0303, 0x0304, 0x0300):
            break
        if record_len > 16384 + 2048:  # TLS max record size + overhead
            break

        record_end = offset + 5 + record_len
        if record_end > len(payload):
            break

        record_data = payload[offset + 5 : record_end]

        if content_type == TLS_HANDSHAKE and len(record_data) >= 4:
            hs_type = record_data[0]
            hs_len = struct.unpack_from("!I", b"\x00" + record_data[1:4])[0]
            hs_body = record_data[4 : 4 + hs_len]

            if hs_type == HS_CLIENT_HELLO:
                parse_client_hello(hs_body, session)
                found = True
            elif hs_type == HS_SERVER_HELLO:
                parse_server_hello(hs_body, session)
                found = True
            elif hs_type == HS_CERTIFICATE and session.cert_der is None:
                session.cert_der = _extract_first_cert_der(hs_body, session)
                found = True

        offset = record_end
        found = True

    return found


# QUIC parsing

QUIC_LONG_HEADER_MASK = 0x80
QUIC_FIXED_BIT = 0x40
QUIC_INITIAL_PACKET_TYPE = 0x00  # bits 4-5


def try_parse_quic(payload: bytes, session: QUICSession) -> bool:
    """Try to parse QUIC Initial packet header."""
    if len(payload) < 7:
        return False

    first_byte = payload[0]
    # Long header: bit 7 set; fixed bit: bit 6 set
    if not (first_byte & QUIC_LONG_HEADER_MASK) or not (first_byte & QUIC_FIXED_BIT):
        return False

    packet_type = (first_byte & 0x30) >> 4

    try:
        version = struct.unpack_from("!I", payload, 1)[0]
        session.version = version

        offset = 5
        # DCID length + DCID
        dcid_len = payload[offset]
        offset += 1 + dcid_len
        # SCID length + SCID
        scid_len = payload[offset]
        offset += 1 + scid_len

        # For Initial packets (type 0x00), there's a token
        if packet_type == QUIC_INITIAL_PACKET_TYPE:
            token_len = payload[offset]
            # Variable-length integer for token_length; simplified: assume 1-byte
            offset += 1 + token_len

        return True
    except (struct.error, IndexError):
        return False
