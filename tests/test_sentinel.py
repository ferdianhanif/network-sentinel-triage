import os
import tempfile
from unittest.mock import patch, MagicMock
import pytest
import yaml

from src.models import (
    LayerType,
    ProbeTarget,
    ProbeResult,
    ProbeStatus,
    HostTelemetrySnapshot,
    IncidentPacket,
)
from src.probers.icmp_prober import ICMPProber
from src.probers.tcp_prober import TCPProber
from src.probers.http_prober import HTTPProber
from src.triage.dns_triage import DNSTriage
from src.triage.traceroute_triage import TracerouteTriage
from src.triage.host_telemetry import HostTelemetryCollector
from src.notifiers.telegram_notifier import TelegramNotifier
from src.engine import SentinelEngine


def test_models_serialization():
    target_data = {
        "name": "test-icmp",
        "type": "icmp",
        "host": "127.0.0.1",
        "threshold": 3,
        "timeout_seconds": 1.5,
    }
    target = ProbeTarget.from_dict(target_data)
    assert target.name == "test-icmp"
    assert target.target_type == LayerType.ICMP
    assert target.threshold == 3
    assert target.timeout_seconds == 1.5

    result = ProbeResult(
        target_name="test-icmp",
        status=ProbeStatus.HEALTHY,
        latency_ms=1.2,
        timestamp="2026-10-12T00:00:00Z",
    )
    result_dict = result.to_dict()
    assert result_dict["status"] == "healthy"
    assert result_dict["latency_ms"] == 1.2

    telemetry = HostTelemetrySnapshot(
        cpu_percent=15.0,
        memory_percent=45.0,
        memory_used_mb=2000.0,
        memory_total_mb=4000.0,
        top_processes=[{"name": "test", "pid": 1, "memory_percent": 2.0, "cpu_percent": 1.0}],
        oom_events=[],
    )
    packet = IncidentPacket(
        target_name="test-icmp",
        target_type="icmp",
        endpoint="ICMP://127.0.0.1",
        timestamp="2026-10-12T00:00:00Z",
        trigger_reason="Timeout",
        traceroute_output="Hop 1: 127.0.0.1",
        dns_resolution="Bypassed",
        host_telemetry=telemetry,
        root_cause_hypothesis="Testing hypothesis",
    )
    packet_dict = packet.to_dict()
    assert packet_dict["target_name"] == "test-icmp"
    assert packet_dict["host_telemetry"]["cpu_percent"] == 15.0


def test_icmp_rtt_extraction():
    target = ProbeTarget(name="ping-test", target_type=LayerType.ICMP, host="127.0.0.1")
    prober = ICMPProber(target)

    # Windows style output
    win_out = "Reply from 127.0.0.1: bytes=32 time=4ms TTL=128"
    assert prober._extract_rtt(win_out) == 4.0

    # Linux style output
    linux_out = "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.45 ms"
    assert prober._extract_rtt(linux_out) == 0.45

    # Less than 1ms
    sub_ms = "Reply from 127.0.0.1: bytes=32 time<1ms TTL=128"
    assert prober._extract_rtt(sub_ms) == 1.0


def test_tcp_prober_connection_refused():
    # Connecting to an unused high port on localhost should refuse connection immediately
    target = ProbeTarget(
        name="unused-port",
        target_type=LayerType.TCP,
        host="127.0.0.1",
        port=59998,
        timeout_seconds=0.5,
    )
    prober = TCPProber(target)
    result = prober.probe()
    assert result.status == ProbeStatus.DOWN
    assert "refused" in (result.error or "").lower() or "timeout" in (result.error or "").lower()


def test_dns_triage_direct_ip():
    triage = DNSTriage()
    msg, success = triage.run("192.168.1.1")
    assert success is True
    assert "direct IP address" in msg


def test_traceroute_loopback():
    trace = TracerouteTriage()
    raw, summary = trace.run("127.0.0.1")
    assert "Loopback" in raw
    assert "Loopback route active" in summary


def test_host_telemetry_collection():
    collector = HostTelemetryCollector()
    telemetry = collector.collect()
    assert telemetry.cpu_percent >= 0.0
    assert telemetry.memory_percent > 0.0
    assert telemetry.memory_total_mb > 0.0
    assert isinstance(telemetry.top_processes, list)


def test_telegram_message_formatting_no_emojis():
    telemetry = HostTelemetrySnapshot(
        cpu_percent=12.5,
        memory_percent=60.0,
        memory_used_mb=3000.0,
        memory_total_mb=5000.0,
        top_processes=[{"name": "nginx", "pid": 100, "memory_percent": 5.0, "cpu_percent": 1.0}],
        oom_events=["No kernel OOM events detected"],
    )
    packet = IncidentPacket(
        target_name="api-gateway",
        target_type="tcp",
        endpoint="TCP://10.0.0.1:443",
        timestamp="2026-10-12T12:00:00Z",
        trigger_reason="Connection refused",
        traceroute_output="Hop 1: 10.0.0.1",
        dns_resolution="Resolved in 2ms",
        host_telemetry=telemetry,
        root_cause_hypothesis="Target service daemon not running.",
    )
    notifier = TelegramNotifier()
    msg = notifier.format_incident_message(packet)

    # Check alert structure
    assert "[INCIDENT ALERT]" in msg
    assert "Target: api-gateway (TCP)" in msg
    assert "ROOT CAUSE HYPOTHESIS:" in msg
    # Assert strictly no emojis in the message
    for ch in msg:
        assert ord(ch) < 127 or ord(ch) in (0x20, 0x0A, 0x0D), f"Non-ASCII / potential emoji character found: {ch!r} (code {ord(ch)})"


def test_flap_damping_and_debounce():
    with tempfile.NamedTemporaryFile("w+", suffix=".yaml", delete=False) as tf:
        config_content = {
            "global": {
                "probe_interval_seconds": 1,
                "cooldown_seconds": 30,
                "log_file": "logs/test_sentinel.log",
                "incident_log_file": "logs/test_incidents.jsonl",
            },
            "telegram": {"enabled": False},
            "targets": [
                {
                    "name": "flapping-mock",
                    "type": "tcp",
                    "host": "127.0.0.1",
                    "port": 59997,
                    "threshold": 3,
                    "timeout_seconds": 0.2,
                }
            ],
        }
        yaml.dump(config_content, tf)
        config_file = tf.name

    try:
        engine = SentinelEngine(config_path=config_file)
        target = engine.targets[0]
        state = engine.states[target.name]

        # Cycle 1: Failure 1 -> below threshold (threshold=3)
        res1 = engine.execute_probe(target)
        engine._handle_result(target, res1)
        assert state.consecutive_failures == 1
        assert state.last_alert_time == 0.0

        # Cycle 2: Failure 2 -> still below threshold
        res2 = engine.execute_probe(target)
        engine._handle_result(target, res2)
        assert state.consecutive_failures == 2
        assert state.last_alert_time == 0.0

        # Cycle 3: Failure 3 -> meets threshold, triggers alert!
        res3 = engine.execute_probe(target)
        engine._handle_result(target, res3)
        assert state.consecutive_failures == 3
        assert state.last_alert_time > 0.0

        saved_alert_time = state.last_alert_time

        # Cycle 4: Failure 4 -> cooldown in effect, does not re-alert
        res4 = engine.execute_probe(target)
        engine._handle_result(target, res4)
        assert state.consecutive_failures == 4
        assert state.last_alert_time == saved_alert_time

    finally:
        if os.path.exists(config_file):
            os.remove(config_file)
