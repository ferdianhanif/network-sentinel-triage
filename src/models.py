from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, List, Dict, Any


class LayerType(str, Enum):
    ICMP = "icmp"
    TCP = "tcp"
    HTTP = "http"


class ProbeStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DOWN = "down"


@dataclass
class ProbeTarget:
    name: str
    target_type: LayerType
    host: Optional[str] = None
    port: Optional[int] = None
    url: Optional[str] = None
    expected_status: int = 200
    threshold: int = 3
    timeout_seconds: float = 2.0
    verify_ssl: bool = True

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProbeTarget":
        raw_type = data.get("type", "icmp").lower()
        return cls(
            name=data["name"],
            target_type=LayerType(raw_type),
            host=data.get("host"),
            port=data.get("port"),
            url=data.get("url"),
            expected_status=data.get("expected_status", 200),
            threshold=data.get("threshold", 3),
            timeout_seconds=float(data.get("timeout_seconds", 2.0)),
            verify_ssl=bool(data.get("verify_ssl", True)),
        )


@dataclass
class ProbeResult:
    target_name: str
    status: ProbeStatus
    latency_ms: float
    timestamp: str
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HostTelemetrySnapshot:
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_total_mb: float
    top_processes: List[Dict[str, Any]]
    oom_events: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IncidentPacket:
    target_name: str
    target_type: str
    endpoint: str
    timestamp: str
    trigger_reason: str
    traceroute_output: str
    dns_resolution: str
    host_telemetry: HostTelemetrySnapshot
    root_cause_hypothesis: str

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if isinstance(self.host_telemetry, HostTelemetrySnapshot):
            data["host_telemetry"] = self.host_telemetry.to_dict()
        return data
