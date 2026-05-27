from datetime import datetime, timezone, timedelta
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import NameOID

from models import (
    CertInfo,
    INSECURE_VERSIONS,
    WARN_EXPIRY_DAYS,
    WEAK_CIPHER_KEYWORDS,
    TLSVersion,
    TLSSession,
)


def parse_cert_der(der: bytes) -> Optional[CertInfo]:
    try:
        cert = x509.load_der_x509_certificate(der)
        now = datetime.now(timezone.utc)

        def _cn(name) -> Optional[str]:
            attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
            return attrs[0].value if attrs else None

        not_after = cert.not_valid_after_utc

        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            raw = san_ext.value.get_values_for_type(x509.DNSName)
            # cryptography >= 42: returns strings directly; older: objects with .value
            san = [v if isinstance(v, str) else v.value for v in raw]
        except x509.ExtensionNotFound:
            san = []

        sig_alg = cert.signature_hash_algorithm
        sig_name = sig_alg.name if sig_alg else "unknown"

        return CertInfo(
            subject_cn=_cn(cert.subject),
            issuer_cn=_cn(cert.issuer),
            not_after=not_after,
            san=san,
            sig_algorithm=sig_name,
            is_self_signed=cert.issuer == cert.subject,
            is_expired=not_after < now,
            is_expiring_soon=not_after >= now and (not_after - now) < timedelta(days=WARN_EXPIRY_DAYS),
            is_weak_sig=sig_name.lower() in ("sha1", "md5", "md2"),
        )
    except Exception:
        return None


def get_security_issues(session: TLSSession) -> list[str]:
    issues: list[str] = []

    ver = session.negotiated_version
    if ver == TLSVersion.UNKNOWN:
        ver = session.tls_version
    if ver in INSECURE_VERSIONS:
        issues.append(f"устаревшая версия {ver.value}")

    if session.cipher_suite:
        name_lower = session.cipher_suite.lower()
        if any(kw in name_lower for kw in WEAK_CIPHER_KEYWORDS):
            issues.append(f"слабый шифр {session.cipher_suite}")

    ci = session.cert_info
    if ci:
        if ci.is_expired:
            date_str = ci.not_after.strftime("%Y-%m-%d") if ci.not_after else "?"
            issues.append(f"сертификат истёк {date_str}")
        elif ci.is_expiring_soon and ci.not_after:
            days = (ci.not_after - datetime.now(timezone.utc)).days
            issues.append(f"сертификат истекает через {days} д.")
        if ci.is_self_signed:
            issues.append("самоподписанный сертификат")
        if ci.is_weak_sig:
            issues.append(f"слабая подпись {ci.sig_algorithm.upper()}")

    return issues