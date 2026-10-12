import socket
import time
from datetime import datetime, timezone
from src.models import ProbeTarget, ProbeResult, ProbeStatus


class TCPProber:
    """
    Layer 4 TCP handshake health prober.
    Tests TCP socket connectivity and handshake duration.
    """

    def __init__(self, target: ProbeTarget):
        self.target = target

    def probe(self) -> ProbeResult:
        host = self.target.host or "127.0.0.1"
        port = self.target.port or 80
        timeout = self.target.timeout_seconds
        now_str = datetime.now(timezone.utc).isoformat()

        start_time = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            sock.connect((host, port))
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            sock.close()

            return ProbeResult(
                target_name=self.target.name,
                status=ProbeStatus.HEALTHY,
                latency_ms=elapsed_ms,
                timestamp=now_str,
                error=None,
                details={"host": host, "port": port},
            )

        except socket.timeout:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ProbeResult(
                target_name=self.target.name,
                status=ProbeStatus.DOWN,
                latency_ms=elapsed_ms,
                timestamp=now_str,
                error=f"TCP connect timeout after {timeout}s",
                details={"host": host, "port": port, "reason": "timeout"},
            )
        except ConnectionRefusedError:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ProbeResult(
                target_name=self.target.name,
                status=ProbeStatus.DOWN,
                latency_ms=elapsed_ms,
                timestamp=now_str,
                error=f"Connection refused by host {host}:{port}",
                details={"host": host, "port": port, "reason": "connection_refused"},
            )
        except socket.gaierror as exc:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ProbeResult(
                target_name=self.target.name,
                status=ProbeStatus.DOWN,
                latency_ms=elapsed_ms,
                timestamp=now_str,
                error=f"DNS resolution failed for host {host}: {str(exc)}",
                details={"host": host, "port": port, "reason": "dns_failure"},
            )
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ProbeResult(
                target_name=self.target.name,
                status=ProbeStatus.DOWN,
                latency_ms=elapsed_ms,
                timestamp=now_str,
                error=f"TCP socket error: {str(exc)}",
                details={"host": host, "port": port, "reason": type(exc).__name__},
            )
        finally:
            try:
                sock.close()
            except Exception:
                pass
