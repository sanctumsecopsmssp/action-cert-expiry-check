#!/usr/bin/env python3
"""Check X.509 certificate expiry from files or live TLS endpoints."""
import argparse
import glob
import os
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography import x509
except ImportError:
    print("error: cryptography==45.0.7 is required; install requirements.txt", file=sys.stderr)
    sys.exit(4)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Check certificate expiry from files and TLS endpoints.")
    parser.add_argument("--paths", default="")
    parser.add_argument("--endpoints", default="")
    parser.add_argument("--warn-days", default="30")
    parser.add_argument("--fail-days", default="7")
    parser.add_argument("--flag-pre-quantum", default="true", choices=("true", "false"))
    return parser.parse_args()


def write_github_output(values):
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            for key, value in values.items():
                handle.write(f"{key}={value}\n")


def write_summary(markdown):
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(markdown + "\n")


def certificate_record(blob, source):
    certificate = x509.load_pem_x509_certificate(blob) if b"-----BEGIN CERTIFICATE-----" in blob else x509.load_der_x509_certificate(blob)
    if hasattr(certificate, "not_valid_after_utc"):
        expires = certificate.not_valid_after_utc
        starts = certificate.not_valid_before_utc
    else:
        expires = certificate.not_valid_after.replace(tzinfo=timezone.utc)
        starts = certificate.not_valid_before.replace(tzinfo=timezone.utc)
    signature = certificate.signature_algorithm_oid._name or certificate.signature_algorithm_oid.dotted_string
    key_type = certificate.public_key().__class__.__name__.replace("PublicKey", "")
    return {
        "source": source,
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "serial": format(certificate.serial_number, "X"),
        "not_before": starts.isoformat(),
        "not_after": expires.isoformat(),
        "signature_algorithm": signature,
        "key_type": key_type,
        "expires": expires,
    }


def endpoint_parts(value):
    value = value.strip()
    if value.startswith("["):
        host, separator, port = value[1:].partition("]:")
        return host, int(port) if separator else 443
    host, separator, port = value.rpartition(":")
    if separator and host and port.isdigit():
        return host, int(port)
    return value, 443


def read_endpoint(value):
    host, port = endpoint_parts(value)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as connection:
        with context.wrap_socket(connection, server_hostname=host) as tls_connection:
            return tls_connection.getpeercert(binary_form=True)


def file_blobs(specification):
    results = []
    for raw in specification.splitlines():
        pattern = raw.strip()
        if not pattern:
            continue
        matches = glob.glob(pattern, recursive=True)
        if not matches and Path(pattern).is_file():
            matches = [pattern]
        for item in matches:
            path = Path(item)
            if path.is_file():
                results.append((str(path), path.read_bytes()))
    return results


def is_pre_quantum(record):
    value = (record["signature_algorithm"] + " " + record["key_type"]).lower()
    return any(token in value for token in ("rsa", "ecdsa", "dsa", "ed25519", "ed448"))


def main():
    args = parse_arguments()
    try:
        warn_days, fail_days = int(args.warn_days), int(args.fail_days)
    except ValueError:
        print("error: warn-days and fail-days must be integers", file=sys.stderr)
        return 2
    if warn_days < 0 or fail_days < 0:
        print("error: warn-days and fail-days must be non-negative", file=sys.stderr)
        return 2
    records, errors = [], []
    for source, blob in file_blobs(args.paths):
        try:
            records.append(certificate_record(blob, source))
        except Exception as exc:
            errors.append(f"{source}: {exc}")
    for endpoint in (item.strip() for item in args.endpoints.splitlines() if item.strip()):
        try:
            records.append(certificate_record(read_endpoint(endpoint), endpoint))
        except Exception as exc:
            errors.append(f"{endpoint}: {exc}")
    if not records and not errors:
        print("error: provide at least one matching certificate path or TLS endpoint", file=sys.stderr)
        return 2
    now = datetime.now(timezone.utc)
    expiring = 0
    failing = 0
    lines = ["## Certificate Expiry Check", "", "| Source | Expires | Days remaining | Signature algorithm | Key type |", "| --- | --- | ---: | --- | --- |"]
    for record in records:
        days = (record["expires"] - now).total_seconds() / 86400
        record["days_remaining"] = round(days, 2)
        record["pre_quantum"] = args.flag_pre_quantum == "true" and is_pre_quantum(record)
        if days <= warn_days:
            expiring += 1
        if days <= fail_days:
            failing += 1
        lines.append("| {0} | {1} | {2:.2f} | {3} | {4} |".format(record["source"], record["expires"].date().isoformat(), days, record["signature_algorithm"], record["key_type"]))
    if errors:
        lines.extend(["", "### Retrieval or parsing errors", ""])
        lines.extend("- " + item for item in errors)
    soonest = min((record["expires"] for record in records), default=None)
    lines.extend(["", f"- Certificates inside warning threshold: **{expiring}**", f"- Pre-quantum signature findings: **{sum(1 for record in records if record['pre_quantum'])}**"])
    summary = "\n".join(lines)
    write_github_output({"expiring-count": expiring, "soonest-expiry": soonest.date().isoformat() if soonest else ""})
    write_summary(summary)
    print(summary)
    if errors:
        return 3
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
