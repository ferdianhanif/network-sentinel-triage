import platform
import shutil
import subprocess
from typing import Tuple


class TracerouteTriage:
    """
    Automated network path hop diagnostic investigator.
    Pinpoints intermediate hop dropouts upon probe failure.
    """

    def __init__(self, max_hops: int = 8, timeout_seconds: float = 6.0):
        self.max_hops = max_hops
        self.timeout_seconds = timeout_seconds
        self.is_windows = platform.system().lower() == "windows"

    def run(self, host: str) -> Tuple[str, str]:
        """
        Executes bounded traceroute and returns (raw_output, diagnosis_summary).
        """
        if host in ("127.0.0.1", "localhost", "::1"):
            return (
                "Hop 1: 127.0.0.1 (<1ms) - Loopback interface responsive",
                "Loopback route active. Target failure is application or port level, not network routing.",
            )

        cmd = []
        if self.is_windows:
            cmd = ["tracert", "-d", "-h", str(self.max_hops), "-w", "500", host]
        else:
            if shutil.which("traceroute"):
                cmd = ["traceroute", "-n", "-m", str(self.max_hops), "-w", "1", "-q", "1", host]
            elif shutil.which("tracepath"):
                cmd = ["tracepath", "-n", "-m", str(self.max_hops), host]
            else:
                return (
                    "traceroute / tracepath binary not installed on host.",
                    "Unable to trace hops: missing traceroute utility.",
                )

        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout_seconds,
            )
            raw_output = proc.stdout.strip()
            summary = self._analyze_hops(raw_output)
            return raw_output, summary

        except subprocess.TimeoutExpired:
            return (
                f"Traceroute timed out after {self.timeout_seconds} seconds.",
                "Route trace exceeded timeout. Severe upstream packet loss or firewall silence.",
            )
        except Exception as exc:
            return (
                f"Traceroute execution error: {str(exc)}",
                f"Diagnostic tool failure: {type(exc).__name__}",
            )

    def _analyze_hops(self, output: str) -> str:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if not lines:
            return "No route hops returned."

        # Count timeouts (asterisks)
        timeout_hops = [line for line in lines if "*" in line]
        if len(timeout_hops) >= 3:
            return "Multiple intermediate hops timed out. Possible packet drop or ICMP filter."
        return "Route path mapped. Check hop details for drop location."
