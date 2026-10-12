import platform
import re
import subprocess
import time
from datetime import datetime, timezone
from typing import Optional
from src.models import ProbeTarget, ProbeResult, ProbeStatus


class ICMPProber:
    """
    Layer 3 ICMP ping health prober.
    Supports both Linux and Windows platform commands.
    """

    def __init__(self, target: ProbeTarget):
        self.target = target
        self.is_windows = platform.system().lower() == "windows"

    def probe(self) -> ProbeResult:
        host = self.target.host or "127.0.0.1"
        timeout_ms = int(self.target.timeout_seconds * 1000)
        timeout_sec = max(1, int(self.target.timeout_seconds))
        now_str = datetime.now(timezone.utc).isoformat()

        if self.is_windows:
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout_sec), host]

        start_time = time.perf_counter()
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.target.timeout_seconds + 1.0,
            )
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            stdout = proc.stdout

            if proc.returncode != 0:
                return ProbeResult(
                    target_name=self.target.name,
                    status=ProbeStatus.DOWN,
                    latency_ms=elapsed_ms,
                    timestamp=now_str,
                    error=f"Ping exit code {proc.returncode}: destination unreachable or timed out",
                    details={"raw_output": stdout.strip(), "command": " ".join(cmd)},
                )

            # Extract RTT
            rtt = self._extract_rtt(stdout) or elapsed_ms
            return ProbeResult(
                target_name=self.target.name,
                status=ProbeStatus.HEALTHY,
                latency_ms=rtt,
                timestamp=now_str,
                error=None,
                details={"packet_loss_percent": 0.0, "command": " ".join(cmd)},
            )

        except subprocess.TimeoutExpired:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ProbeResult(
                target_name=self.target.name,
                status=ProbeStatus.DOWN,
                latency_ms=elapsed_ms,
                timestamp=now_str,
                error=f"Ping timed out after {self.target.timeout_seconds}s",
                details={"timeout_seconds": self.target.timeout_seconds},
            )
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ProbeResult(
                target_name=self.target.name,
                status=ProbeStatus.DOWN,
                latency_ms=elapsed_ms,
                timestamp=now_str,
                error=f"ICMP execution failed: {str(exc)}",
                details={"exception": type(exc).__name__},
            )

    def _extract_rtt(self, output: str) -> Optional[float]:
        # Windows: "time=12ms" or "time<1ms"
        # Linux: "time=12.4 ms"
        match = re.search(r"time[=<]([0-9.]+)\s*ms", output, re.IGNORECASE)
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                return None
        return None
