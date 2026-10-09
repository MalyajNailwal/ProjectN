"""Inspect the certificate and negotiated TLS connection for one HTTPS origin."""

from __future__ import annotations

import socket
import ssl
import time
from urllib.parse import urlparse

from app.core import finding, gap
from app.web_probe import CONFIG


def inspect_tls(url: str, host: str) -> tuple[list[dict], dict, list[dict]]:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return [], {"id": "tls", "label": "TLS certificate and connection", "state": "skipped", "summary": "Target URL uses HTTP"}, [gap("https_not_selected", "The selected URL does not use HTTPS.", "Scan the HTTPS origin if available and configure redirect from HTTP.", "tls")]
    port = parsed.port or 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=CONFIG["timeout_seconds"]) as tcp:
            with context.wrap_socket(tcp, server_hostname=host) as connection:
                cert = connection.getpeercert()
                protocol = connection.version()
                cipher = connection.cipher()
    except ssl.SSLCertVerificationError as exc:
        issue = finding("tls", "TLS certificate validation failed", "high", f"{host}:{port}", f"Certificate verification error: {exc.verify_message}", "Replace or renew the certificate and ensure its chain and hostname are valid, then rescan.", "tls:verification", "observed")
        return [issue], {"id": "tls", "label": "TLS certificate and connection", "state": "partial", "summary": "Certificate validation failed"}, [gap("tls_certificate_invalid", "Verified TLS connection could not be established.", "Fix the certificate chain or hostname and rerun TLS inspection.", "tls")]
    except (OSError, ssl.SSLError, ValueError) as exc:
        return [], {"id": "tls", "label": "TLS certificate and connection", "state": "failed", "summary": type(exc).__name__}, [gap("tls_unavailable", "TLS connection could not be inspected.", "Check the HTTPS port, network access, and server configuration, then retry.", "tls")]

    expiry = cert.get("notAfter")
    days_left = (ssl.cert_time_to_seconds(expiry) - time.time()) / 86400 if expiry else None
    details = {"host": host, "port": port, "protocol": protocol, "cipher": cipher[0] if cipher else None, "expires_at": expiry, "days_until_expiry": round(days_left, 1) if days_left is not None else None, "subject_alt_names": len(cert.get("subjectAltName", []))}
    found = []
    if days_left is not None and days_left < CONFIG["certificate_expiry_warning_days"]:
        title = "TLS certificate has expired" if days_left < 0 else "TLS certificate expires soon"
        found.append(finding("tls", title, "high" if days_left < 0 else "medium", f"{host}:{port}", f"Verified certificate expires in {days_left:.1f} days.", "Renew the certificate before expiry and verify automatic renewal, then rescan.", "tls:expiry", "observed"))
    return found, {"id": "tls", "label": "TLS certificate and connection", "state": "completed", "summary": f"{protocol}; {details['cipher']}; {details['days_until_expiry']} days to expiry", "details": details}, []
