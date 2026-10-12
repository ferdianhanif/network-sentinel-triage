import time
import urllib.request
import urllib.error
import ssl
from datetime import datetime, timezone
from src.models import ProbeTarget, ProbeResult, ProbeStatus


class HTTPProber:
    """
    Layer 7 HTTP/HTTPS status code and latency health prober.
    """

    def __init__(self, target: ProbeTarget):
        self.target = target

    def probe(self) -> ProbeResult:
        url = self.target.url or "http://127.0.0.1/"
        timeout = self.target.timeout_seconds
        now_str = datetime.now(timezone.utc).isoformat()
        expected = self.target.expected_status or 200

        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Sentinel-Prober/1.0"},
            method="GET",
        )

        # SSL context configuration
        if self.target.verify_ssl:
            ctx = ssl.create_default_context()
        else:
            ctx = ssl._create_unverified_context()

        start_time = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                status_code = response.getcode()
                elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

                if status_code == expected:
                    return ProbeResult(
                        target_name=self.target.name,
                        status=ProbeStatus.HEALTHY,
                        latency_ms=elapsed_ms,
                        timestamp=now_str,
                        error=None,
                        details={"url": url, "status_code": status_code, "expected": expected},
                    )
                else:
                    return ProbeResult(
                        target_name=self.target.name,
                        status=ProbeStatus.DEGRADED,
                        latency_ms=elapsed_ms,
                        timestamp=now_str,
                        error=f"Unexpected HTTP status {status_code} (expected {expected})",
                        details={"url": url, "status_code": status_code, "expected": expected},
                    )

        except urllib.error.HTTPError as err:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            if err.code == expected:
                return ProbeResult(
                    target_name=self.target.name,
                    status=ProbeStatus.HEALTHY,
                    latency_ms=elapsed_ms,
                    timestamp=now_str,
                    error=None,
                    details={"url": url, "status_code": err.code, "expected": expected},
                )
            return ProbeResult(
                target_name=self.target.name,
                status=ProbeStatus.DOWN,
                latency_ms=elapsed_ms,
                timestamp=now_str,
                error=f"HTTP error {err.code}: {err.reason}",
                details={"url": url, "status_code": err.code, "expected": expected},
            )

        except urllib.error.URLError as err:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ProbeResult(
                target_name=self.target.name,
                status=ProbeStatus.DOWN,
                latency_ms=elapsed_ms,
                timestamp=now_str,
                error=f"URL request failed: {err.reason}",
                details={"url": url, "reason": str(err.reason)},
            )

        except TimeoutError:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ProbeResult(
                target_name=self.target.name,
                status=ProbeStatus.DOWN,
                latency_ms=elapsed_ms,
                timestamp=now_str,
                error=f"HTTP request timed out after {timeout}s",
                details={"url": url, "timeout_seconds": timeout},
            )

        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ProbeResult(
                target_name=self.target.name,
                status=ProbeStatus.DOWN,
                latency_ms=elapsed_ms,
                timestamp=now_str,
                error=f"HTTP probe failure: {str(exc)}",
                details={"url": url, "exception": type(exc).__name__},
            )
