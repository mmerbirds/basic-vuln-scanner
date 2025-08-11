# ssl_scan.py (fixed)
from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ScanCommandAttemptStatusEnum,
    ServerScanStatusEnum,
)
from datetime import timezone

def scan_ssl(target, port=443):
    try:
        scanner = Scanner()
        req = ServerScanRequest(server_location=ServerNetworkLocation(hostname=target, port=port))
        scanner.queue_scans([req])

        results = {
            "certificate": None,
            "protocols": [],
            "weak_protocols": [],
            "issues": [],
        }

        for server_scan_result in scanner.get_results():
            # ensure the whole server scan completed
            if server_scan_result.scan_status != ServerScanStatusEnum.COMPLETED:
                results["error"] = f"scan_status={server_scan_result.scan_status}"
                continue

            # certificate info attempt (this is a ScanCommandAttempt)
            certinfo_attempt = server_scan_result.scan_result.certificate_info
            if certinfo_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                certinfo_result = certinfo_attempt.result  # this is the ScanResult
                # iterate deployments (virtual hosts / different certs)
                for deployment in certinfo_result.certificate_deployments:
                    chain = deployment.received_certificate_chain
                    if not chain:
                        continue
                    leaf_cert = chain[0]  # cryptography.x509.Certificate

                    # cryptography added timezone-aware properties in newer versions.
                    not_before = getattr(leaf_cert, "not_valid_before_utc", None) or getattr(leaf_cert, "not_valid_before", None)
                    not_after = getattr(leaf_cert, "not_valid_after_utc", None) or getattr(leaf_cert, "not_valid_after", None)

                    results["certificate"] = {
                        "not_before": not_before.isoformat() if not_before else None,
                        "not_after": not_after.isoformat() if not_after else None,
                        "subject": leaf_cert.subject.rfc4514_string(),
                        "issuer": leaf_cert.issuer.rfc4514_string(),
                        "serial_number": getattr(leaf_cert, "serial_number", None),
                    }
                    break  # stop after first deployment / leaf

            else:
                # certificate scan command failed/errored
                results["certificate_error"] = {
                    "status": certinfo_attempt.status,
                    "reason": certinfo_attempt.error_reason,
                }

            # (You can add same careful handling for other scan commands here,
            #  e.g. cipher suite attempts for protocols, vulnerabilities, etc.)

        return results

    except Exception as e:
        return {"error": str(e)}
