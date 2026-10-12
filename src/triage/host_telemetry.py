import platform
import subprocess
from typing import List, Dict, Any
import psutil
from src.models import HostTelemetrySnapshot


class HostTelemetryCollector:
    """
    Collects immediate system telemetry upon failure detection.
    Freezes CPU, RAM, top resource processes, and kernel OOM signals.
    """

    def collect(self) -> HostTelemetrySnapshot:
        cpu_pct = psutil.cpu_percent(interval=0.2)
        mem = psutil.virtual_memory()

        mem_pct = round(mem.percent, 1)
        mem_used_mb = round(mem.used / (1024 * 1024), 1)
        mem_total_mb = round(mem.total / (1024 * 1024), 1)

        top_procs = self._get_top_processes(limit=5)
        oom_events = self._check_oom_events()

        return HostTelemetrySnapshot(
            cpu_percent=cpu_pct,
            memory_percent=mem_pct,
            memory_used_mb=mem_used_mb,
            memory_total_mb=mem_total_mb,
            top_processes=top_procs,
            oom_events=oom_events,
        )

    def _get_top_processes(self, limit: int = 5) -> List[Dict[str, Any]]:
        procs = []
        for p in psutil.process_iter(["pid", "name", "memory_percent", "cpu_percent"]):
            try:
                info = p.info
                procs.append({
                    "pid": info["pid"],
                    "name": info["name"] or "unknown",
                    "memory_percent": round(info["memory_percent"] or 0.0, 1),
                    "cpu_percent": round(info["cpu_percent"] or 0.0, 1),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Sort by memory consumption descending
        procs.sort(key=lambda x: x["memory_percent"], reverse=True)
        return procs[:limit]

    def _check_oom_events(self) -> List[str]:
        if platform.system().lower() != "linux":
            return ["Non-Linux environment: kernel dmesg OOM check skipped"]

        try:
            cmd = ["dmesg", "--level=err,warn"]
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2.0,
            )
            events = []
            for line in proc.stdout.splitlines()[-100:]:
                lower_line = line.lower()
                if "out of memory" in lower_line or "oom-killer" in lower_line or "killed process" in lower_line:
                    events.append(line.strip())
            return events if events else ["No kernel OOM events detected in recent dmesg buffer"]
        except Exception as exc:
            return [f"Unable to read kernel logs: {type(exc).__name__}"]
