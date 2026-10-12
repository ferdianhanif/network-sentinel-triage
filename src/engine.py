import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml

from src.models import (
    LayerType,
    ProbeTarget,
    ProbeResult,
    ProbeStatus,
    IncidentPacket,
    HostTelemetrySnapshot,
)
from src.probers.icmp_prober import ICMPProber
from src.probers.tcp_prober import TCPProber
from src.probers.http_prober import HTTPProber
from src.triage.traceroute_triage import TracerouteTriage
from src.triage.dns_triage import DNSTriage
from src.triage.host_telemetry import HostTelemetryCollector
from src.notifiers.json_logger import JSONLogger
from src.notifiers.telegram_notifier import TelegramNotifier


class TargetState:
    def __init__(self, target: ProbeTarget):
        self.target = target
        self.consecutive_failures: int = 0
        self.last_alert_time: float = 0.0
        self.current_status: ProbeStatus = ProbeStatus.HEALTHY


class SentinelEngine:
    """
    Core orchestrator: executes probes, manages flap damping,
    and executes first-responder triage upon confirmed failure.
    """

    def __init__(self, config_path: str = "config/targets.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()

        global_cfg = self.config.get("global", {})
        self.interval_seconds = float(global_cfg.get("probe_interval_seconds", 10))
        self.cooldown_seconds = float(global_cfg.get("cooldown_seconds", 60))

        log_file = global_cfg.get("log_file", "logs/sentinel.log")
        incident_file = global_cfg.get("incident_log_file", "logs/incidents.jsonl")
        self.logger = JSONLogger(log_path=log_file, incident_path=incident_file)

        tg_cfg = self.config.get("telegram", {})
        self.notifier = TelegramNotifier(
            bot_token=tg_cfg.get("bot_token"),
            chat_id=tg_cfg.get("chat_id"),
            enabled=tg_cfg.get("enabled", False),
        )

        self.traceroute_triage = TracerouteTriage()
        self.dns_triage = DNSTriage()
        self.telemetry_collector = HostTelemetryCollector()

        self.targets: List[ProbeTarget] = []
        self.states: Dict[str, TargetState] = {}
        self._init_targets()

    def _load_config(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        with open(self.config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def _init_targets(self) -> None:
        raw_targets = self.config.get("targets", [])
        for item in raw_targets:
            target = ProbeTarget.from_dict(item)
            self.targets.append(target)
            self.states[target.name] = TargetState(target)

    def _get_prober(self, target: ProbeTarget):
        if target.target_type == LayerType.ICMP:
            return ICMPProber(target)
        elif target.target_type == LayerType.TCP:
            return TCPProber(target)
        elif target.target_type == LayerType.HTTP:
            return HTTPProber(target)
        raise ValueError(f"Unsupported target type: {target.target_type}")

    def execute_probe(self, target: ProbeTarget) -> ProbeResult:
        prober = self._get_prober(target)
        return prober.probe()

    def run_once(self) -> List[ProbeResult]:
        """
        Executes one complete polling cycle across all configured targets.
        """
        results: List[ProbeResult] = []
        for target in self.targets:
            res = self.execute_probe(target)
            results.append(res)
            self.logger.log_probe(res)
            self._handle_result(target, res)
        return results

    def _handle_result(self, target: ProbeTarget, res: ProbeResult) -> None:
        state = self.states[target.name]
        now = time.time()

        if res.status in (ProbeStatus.DOWN, ProbeStatus.DEGRADED):
            state.consecutive_failures += 1
            if state.consecutive_failures >= target.threshold:
                state.current_status = res.status
                # Check cooldown to prevent notification flooding
                if (now - state.last_alert_time) >= self.cooldown_seconds:
                    incident = self._trigger_triage(target, res)
                    self.logger.log_incident(incident)
                    self.notifier.send_incident(incident)
                    state.last_alert_time = now
        else:
            if state.current_status != ProbeStatus.HEALTHY and state.consecutive_failures >= target.threshold:
                self.logger.logger.info(
                    f"RECOVERY: Target {target.name} recovered to HEALTHY state after {state.consecutive_failures} failures."
                )
            state.consecutive_failures = 0
            state.current_status = ProbeStatus.HEALTHY

    def _trigger_triage(self, target: ProbeTarget, res: ProbeResult) -> IncidentPacket:
        now_str = datetime.now(timezone.utc).isoformat()
        host_to_trace = target.host or self._extract_host_from_url(target.url) or "127.0.0.1"
        endpoint_desc = self._get_endpoint_description(target)

        # 1. Traceroute Triage
        trace_output, trace_summary = self.traceroute_triage.run(host_to_trace)

        # 2. DNS Triage
        dns_output, dns_ok = self.dns_triage.run(host_to_trace)

        # 3. Host Telemetry Snapshot
        telemetry = self.telemetry_collector.collect()

        # 4. Formulate Root Cause Hypothesis
        hypothesis = self._formulate_hypothesis(target, res, dns_ok, trace_summary, telemetry)

        return IncidentPacket(
            target_name=target.name,
            target_type=target.target_type.value,
            endpoint=endpoint_desc,
            timestamp=now_str,
            trigger_reason=res.error or f"Threshold {target.threshold} consecutive failures reached",
            traceroute_output=trace_output,
            dns_resolution=dns_output,
            host_telemetry=telemetry,
            root_cause_hypothesis=hypothesis,
        )

    def simulate_triage(self, target_name: str) -> IncidentPacket:
        """
        Forces an immediate triage execution on a specific target for demonstration.
        """
        matched = next((t for t in self.targets if t.name == target_name), None)
        if not matched:
            raise ValueError(f"Target '{target_name}' not found in configuration")

        synthetic_res = ProbeResult(
            target_name=matched.name,
            status=ProbeStatus.DOWN,
            latency_ms=matched.timeout_seconds * 1000,
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=f"Simulation trigger: forced probe timeout ({matched.timeout_seconds}s)",
            details={"simulation": True},
        )

        incident = self._trigger_triage(matched, synthetic_res)
        self.logger.log_incident(incident)
        self.notifier.send_incident(incident)
        return incident

    def _extract_host_from_url(self, url: Optional[str]) -> str:
        if not url:
            return "127.0.0.1"
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.hostname or url

    def _get_endpoint_description(self, target: ProbeTarget) -> str:
        if target.target_type == LayerType.ICMP:
            return f"ICMP://{target.host}"
        elif target.target_type == LayerType.TCP:
            return f"TCP://{target.host}:{target.port}"
        elif target.target_type == LayerType.HTTP:
            return f"{target.url}"
        return target.name

    def _formulate_hypothesis(
        self,
        target: ProbeTarget,
        res: ProbeResult,
        dns_ok: bool,
        trace_summary: str,
        telemetry: HostTelemetrySnapshot,
    ) -> str:
        if not dns_ok and target.host and not target.host.replace(".", "").isdigit():
            return "Domain name resolution failed. Investigation points to DNS resolver failure or unmapped record."

        if target.target_type == LayerType.TCP and "refused" in (res.error or "").lower():
            return "Network route is established, but target port actively rejected TCP handshake. Service daemon is stopped or port is not bound."

        if telemetry.memory_percent > 90.0:
            return f"Host memory exhaustion detected (RAM at {telemetry.memory_percent}%). Target process may have encountered an out-of-memory freeze."

        if target.target_type == LayerType.ICMP and "unreachable" in (res.error or "").lower():
            return f"Layer 3 reachability failed. Route analysis indicates: {trace_summary}"

        if target.target_type == LayerType.HTTP and res.status == ProbeStatus.DEGRADED:
            return f"HTTP endpoint reachable but application returned abnormal status code: {res.error}"

        return "Service failure detected. Network and host triage data captured for post-incident root cause analysis."
