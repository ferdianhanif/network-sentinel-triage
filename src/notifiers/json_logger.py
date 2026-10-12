import json
import logging
import os
from pathlib import Path
from typing import Dict, Any
from src.models import IncidentPacket, ProbeResult


class JSONLogger:
    """
    Handles structured logging for probe metrics and serialized incident packets.
    """

    def __init__(self, log_path: str = "logs/sentinel.log", incident_path: str = "logs/incidents.jsonl"):
        self.log_path = Path(log_path)
        self.incident_path = Path(incident_path)

        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.incident_path.parent.mkdir(parents=True, exist_ok=True)

        self._setup_logger()

    def _setup_logger(self) -> None:
        self.logger = logging.getLogger("sentinel")
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            formatter = logging.Formatter(
                fmt="%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            fh = logging.FileHandler(self.log_path, encoding="utf-8")
            fh.setFormatter(formatter)
            self.logger.addHandler(fh)

            ch = logging.StreamHandler()
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)

    def log_probe(self, result: ProbeResult) -> None:
        status_upper = result.status.value.upper()
        if result.error:
            msg = f"TARGET [{result.target_name}] STATUS={status_upper} LATENCY={result.latency_ms}ms ERROR=\"{result.error}\""
            self.logger.warning(msg)
        else:
            msg = f"TARGET [{result.target_name}] STATUS={status_upper} LATENCY={result.latency_ms}ms"
            self.logger.info(msg)

    def log_incident(self, packet: IncidentPacket) -> None:
        self.logger.error(
            f"INCIDENT LOGGED: target={packet.target_name} reason=\"{packet.trigger_reason}\""
        )
        packet_dict = packet.to_dict()
        with open(self.incident_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(packet_dict) + "\n")
