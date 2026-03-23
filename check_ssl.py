#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import datetime
import json
import os
import socket
import ssl
import subprocess
import sys
import textwrap
import concurrent.futures
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# ── Thresholds & known-bad lists ──────────────────────────────────────

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
DEPRECATED_PROTOCOLS = {"TLSv1", "TLSv1.0", "TLSv1.1"}
INSECURE_PROTOCOLS = {"SSLv2", "SSLv3"}

WEAK_CIPHER_KEYWORDS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon",
    "MD5",  # MD5 MAC
]

# CBC ciphers are vulnerable to BEAST / Lucky13 on older TLS
CBC_KEYWORD = "CBC"

CERT_EXPIRY_WARN_DAYS = 30
MIN_RSA_BITS = 2048
MIN_ECC_BITS = 256

# Protocols to actively probe (order matters for display)
PROBE_PROTOCOLS = ["SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]


# ── Data structures ───────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str   # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    detail: str


@dataclass
class DomainResult:
    domain: str
    port: int = 443
    reachable: bool = False
    error: Optional[str] = None
    ip_address: Optional[str] = None

    # Certificate info
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    days_until_expiry: Optional[int] = None
    san_list: list = field(default_factory=list)
    self_signed: bool = False
    sig_algorithm: Optional[str] = None
    key_type: Optional[str] = None
    key_bits: Optional[int] = None

    # Protocol & cipher
    negotiated_protocol: Optional[str] = None
    negotiated_cipher: Optional[str] = None
    negotiated_bits: Optional[int] = None
    protocols_supported: list = field(default_factory=list)
    ciphers_offered: list = field(default_factory=list)

    # Headers
    hsts: Optional[str] = None
    hsts_present: bool = False

    # OCSP
    ocsp_stapling: Optional[bool] = None

    # Findings
    findings: list = field(default_factory=list)
    grade: str = "?"


# ── Helpers ────────────────────────────────────────────────────────────

def resolve_domain(domain: str) -> Optional[str]:
    """Return first resolved IP or None."""
    try:
        return socket.getaddrinfo(domain, 443, socket.AF_INET)[0][4][0]
    except socket.gaierror:
        try:
            return socket.getaddrinfo(domain, 443, socket.AF_INET6)[0][4][0]
        except Exception:
            return None


def parse_cert_time(t: str) -> datetime.datetime:
    """Parse the notBefore / notAfter string from ssl.getpeercert()."""
    # Format: 'Mon DD HH:MM:SS YYYY GMT'  or  'YYYYMMDDHHMMSSZ' (openssl)
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ"):
        try:
            return datetime.datetime.strptime(t, fmt)
        except ValueError:
            continue
    return datetime.datetime.utcnow()


def get_san(cert: dict) -> list[str]:
    san = cert.get("subjectAltName", ())
    return [v for _type, v in san]


def subject_cn(cert: dict) -> str:
    for rdn in cert.get("subject", ()):
        for attr, val in rdn:
            if attr == "commonName":
                return val
    return "(unknown)"


def issuer_cn(cert: dict) -> str:
    for rdn in cert.get("issuer", ()):
        for attr, val in rdn:
            if attr in ("commonName", "organizationName"):
                return val
    return "(unknown)"


def _openssl_get_cert_details(domain: str, port: int, timeout: int) -> dict:
    """Use the openssl CLI to grab certificate details not exposed by Python ssl."""
    info = {
        "sig_algorithm": None,
        "key_type": None,
        "key_bits": None,
        "ocsp_stapling": False,
        "serial": None,
    }
    try:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", f"{domain}:{port}",
             "-servername", domain, "-status", "-brief"],
            input=b"",
            capture_output=True,
            timeout=timeout + 5,
        )
        combined = (proc.stdout + proc.stderr).decode(errors="replace")

        # Signature algorithm
        for line in combined.splitlines():
            ll = line.strip().lower()
            if "signature algorithm" in ll:
                info["sig_algorithm"] = line.strip().split(":")[-1].strip()
            if "server public key" in ll or "public key is" in ll:
                # e.g. "Server public key is 2048 bit"
                parts = line.strip().split()
                for i, p in enumerate(parts):
                    if p.isdigit():
                        info["key_bits"] = int(p)
                        break
            if "public key type" in ll or "server temp key" in ll:
                if "rsa" in ll:
                    info["key_type"] = "RSA"
                elif "ec" in ll or "ecdsa" in ll:
                    info["key_type"] = "EC"
                elif "ed25519" in ll:
                    info["key_type"] = "Ed25519"
            if "ocsp response" in ll and "no response" not in ll and "no ocsp" not in ll:
                if "response status: successful" in ll:
                    info["ocsp_stapling"] = True

    except Exception:
        pass

    # Fallback: use x509 to parse the cert directly
    try:
        proc2 = subprocess.run(
            ["openssl", "s_client", "-connect", f"{domain}:{port}",
             "-servername", domain],
            input=b"",
            capture_output=True,
            timeout=timeout + 5,
        )
        pem_data = proc2.stdout
        if b"-----BEGIN CERTIFICATE-----" in pem_data:
            # Extract first PEM block
            start = pem_data.index(b"-----BEGIN CERTIFICATE-----")
            end = pem_data.index(b"-----END CERTIFICATE-----") + len(b"-----END CERTIFICATE-----")
            cert_pem = pem_data[start:end]

            proc3 = subprocess.run(
                ["openssl", "x509", "-noout", "-text", "-serial"],
                input=cert_pem,
                capture_output=True,
                timeout=10,
            )
            x509_text = proc3.stdout.decode(errors="replace")
            for line in x509_text.splitlines():
                ll = line.strip().lower()
                if "signature algorithm" in ll and info["sig_algorithm"] is None:
                    info["sig_algorithm"] = line.strip().split(":")[-1].strip()
                if "public-key:" in ll or "public key:" in ll:
                    # e.g. "Public-Key: (2048 bit)"
                    import re
                    m = re.search(r"\((\d+)\s*bit\)", line)
                    if m:
                        info["key_bits"] = int(m.group(1))
                if "rsa" in ll and "public key" in ll and info["key_type"] is None:
                    info["key_type"] = "RSA"
                if ("ecdsa" in ll or "ec public" in ll or "id-ecpublickey" in ll) and info["key_type"] is None:
                    info["key_type"] = "EC"
                if ll.startswith("serial number"):
                    info["serial"] = line.strip().split(":")[-1].strip()

    except Exception:
        pass

    return info


def _probe_protocol(domain: str, port: int, proto_name: str, timeout: int) -> bool:
    """
    Try connecting with a specific TLS version using openssl s_client.

    Python's ssl module on OpenSSL 3.x refuses to negotiate TLS 1.0/1.1
    because they are disabled at the library level (SECLEVEL >= 1). The
    openssl CLI can bypass this with @SECLEVEL=0, giving us an accurate
    picture of what the *server* actually accepts — which is what matters
    for a vulnerability assessment.
    """
    # Map friendly names to openssl s_client flags
    proto_flags = {
        "SSLv3":   ["-ssl3"],
        "TLSv1.0": ["-tls1"],
        "TLSv1.1": ["-tls1_1"],
        "TLSv1.2": ["-tls1_2"],
        "TLSv1.3": ["-tls1_3"],
    }
    flags = proto_flags.get(proto_name)
    if flags is None:
        return False

    try:
        cmd = [
            "openssl", "s_client",
            "-connect", f"{domain}:{port}",
            "-servername", domain,
        ] + flags

        # For legacy protocols, lower the security level so openssl doesn't
        # refuse the handshake on our side
        if proto_name in ("SSLv3", "TLSv1.0", "TLSv1.1"):
            cmd += ["-cipher", "ALL:@SECLEVEL=0"]

        proc = subprocess.run(
            cmd,
            input=b"",
            capture_output=True,
            timeout=timeout + 5,
        )
        combined = (proc.stdout + proc.stderr).decode(errors="replace")

        # A successful handshake will contain "Protocol  : TLSv..." or
        # "New, TLSv..." in the output. A failure shows "wrong version"
        # or "no protocols available" or a non-zero exit.
        lower = combined.lower()
        if proc.returncode == 0 and (
            "protocol  :" in lower
            or "new," in lower
            or "cipher is" in lower
        ):
            # Double-check it's not reporting an error
            if "error" not in lower or "verify error" in lower:
                return True
            # "verify error" is just a cert trust issue, handshake succeeded
            if "verify error" in lower:
                return True
        return False

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _get_ciphers_for_protocol(domain: str, port: int, proto_name: str, timeout: int) -> list[str]:
    """
    Return the cipher the server negotiates for a given TLS version.
    Uses openssl s_client so legacy protocols (TLS 1.0/1.1) are testable
    even when the local Python ssl module blocks them.
    """
    proto_flags = {
        "SSLv3":   ["-ssl3"],
        "TLSv1.0": ["-tls1"],
        "TLSv1.1": ["-tls1_1"],
        "TLSv1.2": ["-tls1_2"],
        "TLSv1.3": ["-tls1_3"],
    }
    flags = proto_flags.get(proto_name)
    if flags is None:
        return []

    ciphers = []
    try:
        cmd = [
            "openssl", "s_client",
            "-connect", f"{domain}:{port}",
            "-servername", domain,
        ] + flags

        if proto_name in ("SSLv3", "TLSv1.0", "TLSv1.1"):
            cmd += ["-cipher", "ALL:@SECLEVEL=0"]

        proc = subprocess.run(
            cmd,
            input=b"",
            capture_output=True,
            timeout=timeout + 5,
        )
        combined = (proc.stdout + proc.stderr).decode(errors="replace")

        import re
        # Look for "Cipher    : ECDHE-RSA-AES128-GCM-SHA256" or
        # "New, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256"
        for line in combined.splitlines():
            stripped = line.strip()
            # "Cipher    : XXX"
            if stripped.lower().startswith("cipher") and ":" in stripped:
                cipher_name = stripped.split(":", 1)[1].strip()
                if cipher_name and cipher_name != "0000" and cipher_name != "(NONE)":
                    ciphers.append(f"{proto_name}: {cipher_name}")
                    break
            # "Cipher is XXX"
            m = re.search(r"[Cc]ipher is (\S+)", stripped)
            if m and m.group(1) not in ("0000", "(NONE)"):
                ciphers.append(f"{proto_name}: {m.group(1)}")
                break

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return ciphers


def _check_hsts(domain: str, timeout: int) -> Optional[str]:
    """Check for HSTS header via a simple HTTP/1.1 HEAD-ish request over TLS."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                req = f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
                ssock.sendall(req.encode())
                resp = b""
                while True:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if b"\r\n\r\n" in resp:
                        break
                headers = resp.decode(errors="replace")
                for line in headers.splitlines():
                    if line.lower().startswith("strict-transport-security"):
                        return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None


# ── Analysis ──────────────────────────────────────────────────────────

def add_finding(result: DomainResult, severity: str, title: str, detail: str):
    result.findings.append(Finding(severity=severity, title=title, detail=detail))


def analyse_findings(result: DomainResult):
    """Generate findings based on collected data."""
    now = datetime.datetime.utcnow()

    # ── Certificate expiry ─────────────────────────────────────────
    if result.not_after:
        expiry = parse_cert_time(result.not_after)
        result.days_until_expiry = (expiry - now).days
        if result.days_until_expiry < 0:
            add_finding(result, "CRITICAL", "Certificate Expired",
                        f"Certificate expired {abs(result.days_until_expiry)} day(s) ago on {result.not_after}")
        elif result.days_until_expiry <= CERT_EXPIRY_WARN_DAYS:
            add_finding(result, "HIGH", "Certificate Expiring Soon",
                        f"Certificate expires in {result.days_until_expiry} day(s) on {result.not_after}")

    # ── Self-signed ────────────────────────────────────────────────
    if result.self_signed:
        add_finding(result, "HIGH", "Self-Signed Certificate",
                    "The certificate is self-signed and will not be trusted by browsers.")

    # ── Hostname mismatch ──────────────────────────────────────────
    if result.san_list:
        import fnmatch
        matched = any(
            fnmatch.fnmatch(result.domain, san.replace("*", "?*"))
            for san in result.san_list
        )
        if not matched:
            # Also check CN
            cn = (result.subject or "").lower()
            if not fnmatch.fnmatch(result.domain.lower(), cn.replace("*", "?*")):
                add_finding(result, "HIGH", "Hostname Mismatch",
                            f"Domain '{result.domain}' does not match SANs: {', '.join(result.san_list[:5])}")

    # ── Weak signature algorithm ───────────────────────────────────
    if result.sig_algorithm:
        sig_lower = result.sig_algorithm.lower()
        if "sha1" in sig_lower or "sha-1" in sig_lower:
            add_finding(result, "HIGH", "SHA-1 Signature",
                        f"Certificate uses deprecated SHA-1 signature ({result.sig_algorithm}).")
        if "md5" in sig_lower:
            add_finding(result, "CRITICAL", "MD5 Signature",
                        f"Certificate uses broken MD5 signature ({result.sig_algorithm}).")

    # ── Weak key size ──────────────────────────────────────────────
    if result.key_bits:
        if result.key_type == "RSA" and result.key_bits < MIN_RSA_BITS:
            add_finding(result, "HIGH", "Weak RSA Key",
                        f"RSA key is only {result.key_bits} bits (minimum recommended: {MIN_RSA_BITS}).")
        if result.key_type == "EC" and result.key_bits < MIN_ECC_BITS:
            add_finding(result, "HIGH", "Weak EC Key",
                        f"EC key is only {result.key_bits} bits (minimum recommended: {MIN_ECC_BITS}).")

    # ── Insecure protocols ─────────────────────────────────────────
    for proto in result.protocols_supported:
        if proto in INSECURE_PROTOCOLS:
            add_finding(result, "CRITICAL", f"{proto} Supported",
                        f"Server supports {proto}, which is fundamentally broken.")
        elif proto in DEPRECATED_PROTOCOLS:
            add_finding(result, "HIGH", f"{proto} Supported",
                        f"Server supports deprecated {proto}. Should be disabled (POODLE, BEAST, etc.).")

    # ── TLS 1.3 not supported ─────────────────────────────────────
    if "TLSv1.3" not in result.protocols_supported and result.protocols_supported:
        add_finding(result, "MEDIUM", "TLS 1.3 Not Supported",
                    "Server does not support TLS 1.3. Consider enabling it for best security and performance.")

    # ── Weak ciphers ───────────────────────────────────────────────
    for cipher_line in result.ciphers_offered:
        cipher_upper = cipher_line.upper()
        for kw in WEAK_CIPHER_KEYWORDS:
            if kw.upper() in cipher_upper:
                add_finding(result, "HIGH", f"Weak Cipher ({kw})",
                            f"Server negotiated weak cipher: {cipher_line}")
                break
        else:
            if CBC_KEYWORD in cipher_upper and ("TLSV1.0" in cipher_upper or "TLSV1.1" in cipher_upper):
                add_finding(result, "MEDIUM", "CBC Cipher on Legacy TLS",
                            f"CBC-mode cipher on legacy TLS is vulnerable to BEAST/Lucky13: {cipher_line}")

    # ── HSTS ───────────────────────────────────────────────────────
    if not result.hsts_present:
        add_finding(result, "MEDIUM", "No HSTS Header",
                    "Strict-Transport-Security header is missing. Enables SSL-stripping attacks.")
    else:
        # Check max-age
        if result.hsts:
            import re
            m = re.search(r"max-age=(\d+)", result.hsts, re.I)
            if m and int(m.group(1)) < 15768000:  # < ~6 months
                add_finding(result, "LOW", "Short HSTS max-age",
                            f"HSTS max-age is {m.group(1)} seconds (recommended ≥ 15768000 / ~6 months).")

    # ── OCSP stapling ──────────────────────────────────────────────
    if result.ocsp_stapling is False:
        add_finding(result, "LOW", "No OCSP Stapling",
                    "OCSP stapling not detected. Enabling it improves privacy and performance.")


def compute_grade(result: DomainResult) -> str:
    """Simplified SSL Labs-style letter grade based on findings."""
    if not result.reachable:
        return "T"  # Trust issue / unreachable

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in result.findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    if severity_counts["CRITICAL"] > 0:
        return "F"
    if severity_counts["HIGH"] >= 3:
        return "D"
    if severity_counts["HIGH"] >= 1:
        return "C"
    if severity_counts["MEDIUM"] >= 2:
        return "B-"
    if severity_counts["MEDIUM"] >= 1:
        return "B"
    if severity_counts["LOW"] >= 2:
        return "A-"
    if severity_counts["LOW"] >= 1:
        return "A-"
    return "A"


# ── Main scan function ────────────────────────────────────────────────

def scan_domain(domain: str, port: int = 443, timeout: int = 8) -> DomainResult:
    result = DomainResult(domain=domain, port=port)

    # Resolve
    ip = resolve_domain(domain)
    if not ip:
        result.error = "DNS resolution failed"
        result.grade = "T"
        return result
    result.ip_address = ip

    # ── Primary TLS connection (default context) ──────────────────
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                result.reachable = True
                cert = ssock.getpeercert()
                result.negotiated_protocol = ssock.version()
                cipher_info = ssock.cipher()
                if cipher_info:
                    result.negotiated_cipher = cipher_info[0]
                    result.negotiated_bits = cipher_info[2]

                if cert:
                    result.subject = subject_cn(cert)
                    result.issuer = issuer_cn(cert)
                    result.not_before = cert.get("notBefore")
                    result.not_after = cert.get("notAfter")
                    result.san_list = get_san(cert)
                    result.self_signed = (subject_cn(cert) == issuer_cn(cert))
    except ssl.SSLCertVerificationError as e:
        result.error = f"Certificate verification failed: {e}"
        result.reachable = True  # Server responded, cert is bad
        # Try without verification to still get cert details
        try:
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with ctx2.wrap_socket(sock, server_hostname=domain) as ssock:
                    result.negotiated_protocol = ssock.version()
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        result.negotiated_cipher = cipher_info[0]
                        result.negotiated_bits = cipher_info[2]
                    cert = ssock.getpeercert(binary_form=False)
        except Exception:
            pass
        add_finding(result, "CRITICAL", "Certificate Verification Failed", str(e))
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result.error = f"Connection failed: {e}"
        result.grade = "T"
        return result

    # ── OpenSSL CLI details (sig algo, key size, OCSP) ────────────
    ossl = _openssl_get_cert_details(domain, port, timeout)
    result.sig_algorithm = ossl.get("sig_algorithm")
    result.key_type = ossl.get("key_type")
    result.key_bits = ossl.get("key_bits")
    result.ocsp_stapling = ossl.get("ocsp_stapling", False)
    if ossl.get("serial"):
        result.serial = ossl["serial"]

    # ── Protocol probing ──────────────────────────────────────────
    for proto_name in PROBE_PROTOCOLS:
        if _probe_protocol(domain, port, proto_name, timeout):
            result.protocols_supported.append(proto_name)
            # Also grab the negotiated cipher for this protocol
            ciphers = _get_ciphers_for_protocol(domain, port, proto_name, timeout)
            result.ciphers_offered.extend(ciphers)

    # ── HSTS ──────────────────────────────────────────────────────
    hsts_val = _check_hsts(domain, timeout)
    if hsts_val:
        result.hsts = hsts_val
        result.hsts_present = True

    # ── Analyse & grade ───────────────────────────────────────────
    analyse_findings(result)
    result.grade = compute_grade(result)

    return result


# ── Output formatters ─────────────────────────────────────────────────

SEVERITY_COLOURS = {
    "CRITICAL": "\033[91m",  # red
    "HIGH":     "\033[93m",  # yellow
    "MEDIUM":   "\033[33m",  # orange-ish
    "LOW":      "\033[36m",  # cyan
    "INFO":     "\033[90m",  # grey
}
RESET = "\033[0m"
BOLD = "\033[1m"

GRADE_COLOURS = {
    "A":  "\033[92m", "A-": "\033[92m",
    "B":  "\033[93m", "B-": "\033[93m",
    "C":  "\033[33m",
    "D":  "\033[91m",
    "F":  "\033[91m",
    "T":  "\033[90m",
    "?":  "\033[90m",
}


def format_result(r: DomainResult, use_colour: bool = True) -> str:
    """Format a single domain result as a text block."""
    lines = []

    gc = GRADE_COLOURS.get(r.grade, "") if use_colour else ""
    bold = BOLD if use_colour else ""
    reset = RESET if use_colour else ""

    lines.append(f"\n{'═' * 72}")
    lines.append(f"  {bold}{r.domain}:{r.port}{reset}   →   Grade: {gc}{bold}{r.grade}{reset}")
    lines.append(f"{'═' * 72}")

    if r.ip_address:
        lines.append(f"  IP Address       : {r.ip_address}")
    if r.error:
        lines.append(f"  Error            : {r.error}")
    if not r.reachable:
        lines.append(f"  Status           : UNREACHABLE")
        return "\n".join(lines)

    lines.append(f"  Subject CN       : {r.subject or '—'}")
    lines.append(f"  Issuer           : {r.issuer or '—'}")
    lines.append(f"  Valid From       : {r.not_before or '—'}")
    if r.days_until_expiry is not None:
        lines.append(f"  Valid Until      : {r.not_after or '—'}  ({r.days_until_expiry} days remaining)")
    else:
        lines.append(f"  Valid Until      : {r.not_after or '—'}")
    lines.append(f"  Self-Signed      : {'Yes ⚠' if r.self_signed else 'No'}")
    lines.append(f"  Sig Algorithm    : {r.sig_algorithm or '—'}")
    lines.append(f"  Key              : {r.key_type or '?'} {r.key_bits or '?'} bits")
    lines.append(f"  Serial           : {r.serial or '—'}")

    lines.append(f"\n  Negotiated       : {r.negotiated_protocol}  /  {r.negotiated_cipher} ({r.negotiated_bits} bits)")
    lines.append(f"  Protocols        : {', '.join(r.protocols_supported) if r.protocols_supported else '—'}")
    if r.ciphers_offered:
        lines.append(f"  Ciphers Seen     :")
        for c in r.ciphers_offered:
            lines.append(f"      {c}")

    lines.append(f"  HSTS             : {'Yes — ' + (r.hsts or '') if r.hsts_present else 'No ⚠'}")
    lines.append(f"  OCSP Stapling    : {'Yes' if r.ocsp_stapling else 'No'}")

    if r.findings:
        lines.append(f"\n  {'─' * 60}")
        lines.append(f"  FINDINGS ({len(r.findings)}):")
        for f in sorted(r.findings, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x.severity)):
            sc = SEVERITY_COLOURS.get(f.severity, "") if use_colour else ""
            lines.append(f"    {sc}[{f.severity}]{reset} {f.title}")
            lines.append(f"           {f.detail}")
    else:
        lines.append(f"\n  ✅  No issues found.")

    return "\n".join(lines)


def format_summary(results: list[DomainResult], use_colour: bool = True) -> str:
    """Format the summary table as a text block."""
    reset = RESET if use_colour else ""
    lines = []

    lines.append(f"\n\n{'═' * 72}")
    lines.append(f"  SUMMARY")
    lines.append(f"{'═' * 72}")
    lines.append(f"  {'Domain':<35} {'Grade':>6}  {'Findings':>8}  {'Critical':>8}  {'High':>6}")
    lines.append(f"  {'─' * 35} {'─' * 6}  {'─' * 8}  {'─' * 8}  {'─' * 6}")
    for r in results:
        crits = sum(1 for f in r.findings if f.severity == "CRITICAL")
        highs = sum(1 for f in r.findings if f.severity == "HIGH")
        gc = GRADE_COLOURS.get(r.grade, "") if use_colour else ""
        lines.append(f"  {r.domain:<35} {gc}{r.grade:>6}{reset}  {len(r.findings):>8}  {crits:>8}  {highs:>6}")

    return "\n".join(lines)


def print_result(r: DomainResult):
    print(format_result(r, use_colour=True))


def write_json_report(results: list[DomainResult], path: str):
    data = []
    for r in results:
        d = asdict(r)
        d["findings"] = [asdict(f) for f in r.findings]
        data.append(d)
    with open(path, "w") as fp:
        json.dump(data, fp, indent=2, default=str)


def write_csv_report(results: list[DomainResult], path: str):
    fieldnames = [
        "domain", "port", "grade", "reachable", "error", "ip_address",
        "subject", "issuer", "not_before", "not_after", "days_until_expiry",
        "self_signed", "sig_algorithm", "key_type", "key_bits",
        "negotiated_protocol", "negotiated_cipher", "negotiated_bits",
        "protocols_supported", "hsts_present", "ocsp_stapling",
        "finding_count", "critical_count", "high_count", "medium_count",
        "findings_summary",
    ]
    with open(path, "w", newline="") as fp:
        w = csv.DictWriter(fp, fieldnames=fieldnames)
        w.writeheader()
        for r in results:
            sev = {}
            for f in r.findings:
                sev[f.severity] = sev.get(f.severity, 0) + 1
            summary = "; ".join(f"[{f.severity}] {f.title}" for f in r.findings)
            w.writerow({
                "domain": r.domain, "port": r.port, "grade": r.grade,
                "reachable": r.reachable, "error": r.error or "",
                "ip_address": r.ip_address or "",
                "subject": r.subject or "", "issuer": r.issuer or "",
                "not_before": r.not_before or "", "not_after": r.not_after or "",
                "days_until_expiry": r.days_until_expiry if r.days_until_expiry is not None else "",
                "self_signed": r.self_signed,
                "sig_algorithm": r.sig_algorithm or "",
                "key_type": r.key_type or "", "key_bits": r.key_bits or "",
                "negotiated_protocol": r.negotiated_protocol or "",
                "negotiated_cipher": r.negotiated_cipher or "",
                "negotiated_bits": r.negotiated_bits or "",
                "protocols_supported": ",".join(r.protocols_supported),
                "hsts_present": r.hsts_present,
                "ocsp_stapling": r.ocsp_stapling,
                "finding_count": len(r.findings),
                "critical_count": sev.get("CRITICAL", 0),
                "high_count": sev.get("HIGH", 0),
                "medium_count": sev.get("MEDIUM", 0),
                "findings_summary": summary,
            })


# ── CLI ───────────────────────────────────────────────────────────────

def load_domains(csv_path: str) -> list[str]:
    """
    Flexible domain loader. Accepts any of:
      1. CSV with a 'domain' column (any case) — uses that column
      2. CSV with no 'domain' column — uses the first column
      3. Plain text file with one domain per line (no commas)
    Strips URLs down to bare hostnames automatically.
    """
    domains = []

    with open(csv_path, newline="") as fp:
        sample = fp.read(4096)
        fp.seek(0)

        # Detect if it's a plain list (no commas at all) vs CSV
        has_commas = "," in sample.split("\n", 1)[0]

        if has_commas:
            reader = csv.DictReader(fp)
            reader.fieldnames = [h.strip().lower() for h in reader.fieldnames]

            # Use 'domain' column if present, otherwise fall back to first column
            if "domain" in reader.fieldnames:
                col = "domain"
            else:
                col = reader.fieldnames[0]
                print(f"[*] No 'domain' column found — using first column: '{col}'", file=sys.stderr)

            for row in reader:
                d = (row.get(col) or "").strip()
                if d and not d.startswith("#"):
                    d = _clean_domain(d)
                    if d:
                        domains.append(d)
        else:
            # Plain text: one domain per line
            for line in fp:
                d = line.strip()
                if d and not d.startswith("#"):
                    d = _clean_domain(d)
                    if d:
                        domains.append(d)

    return domains


def _clean_domain(raw: str) -> str:
    """Strip protocol, path, port, and whitespace from a raw domain string."""
    d = raw.strip()
    d = d.replace("https://", "").replace("http://", "").split("/")[0]
    if ":" in d:
        d = d.rsplit(":", 1)[0]
    return d


def main():
    parser = argparse.ArgumentParser(
        description="Bulk SSL/TLS analyser — checks inspired by Qualys SSL Labs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 ssl_checker.py
              python3 ssl_checker.py -f targets.csv -o scan_results --timeout 12
              python3 ssl_checker.py -f targets.csv --workers 4
        """),
    )
    parser.add_argument("-f", "--file", default="domains.csv", help="Input CSV file (default: domains.csv)")
    parser.add_argument("-o", "--output", default="ssl_report", help="Output file prefix (default: ssl_report)")
    parser.add_argument("-t", "--timeout", type=int, default=8, help="Connection timeout in seconds (default: 8)")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Parallel scan workers (default: 5)")
    parser.add_argument("-p", "--port", type=int, default=443, help="Target port (default: 443)")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[!] File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    domains = load_domains(args.file)
    if not domains:
        print("[!] No domains found in CSV.", file=sys.stderr)
        sys.exit(1)

    print(f"\n{'▄' * 72}")
    print(f"  SSL/TLS Analyser — scanning {len(domains)} domain(s)")
    print(f"  Timeout: {args.timeout}s  |  Workers: {args.workers}  |  Port: {args.port}")
    print(f"{'▀' * 72}")

    results: list[DomainResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        future_map = {
            pool.submit(scan_domain, d, args.port, args.timeout): d
            for d in domains
        }
        for future in concurrent.futures.as_completed(future_map):
            domain = future_map[future]
            try:
                r = future.result()
            except Exception as e:
                r = DomainResult(domain=domain, error=str(e), grade="T")
            results.append(r)
            print_result(r)

    # Sort results by grade severity for reports
    grade_order = {"F": 0, "T": 1, "D": 2, "C": 3, "B-": 4, "B": 5, "A-": 6, "A": 7, "?": 8}
    results.sort(key=lambda r: grade_order.get(r.grade, 99))

    # Write reports
    json_path = f"{args.output}.json"
    csv_path = f"{args.output}.csv"
    txt_path = f"{args.output}.txt"
    write_json_report(results, json_path)
    write_csv_report(results, csv_path)

    # Write plain-text report (domain tables + summary, no ANSI codes)
    with open(txt_path, "w") as fp:
        fp.write(f"{'▄' * 72}\n")
        fp.write(f"  SSL/TLS Analyser Report\n")
        fp.write(f"  Scanned {len(results)} domain(s)  |  {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        fp.write(f"{'▀' * 72}\n")
        for r in results:
            fp.write(format_result(r, use_colour=False))
            fp.write("\n")
        fp.write(format_summary(results, use_colour=False))
        fp.write("\n")

    # Summary (terminal, with colour)
    summary_text = format_summary(results, use_colour=True)
    print(summary_text)

    print(f"\n  Reports saved:")
    print(f"    → {json_path}")
    print(f"    → {csv_path}")
    print(f"    → {txt_path}")
    print()


if __name__ == "__main__":
    main()
