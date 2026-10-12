import json
import logging
import os
import urllib.request
import urllib.error
from typing import Optional
from src.models import IncidentPacket

logger = logging.getLogger("sentinel")


class TelegramNotifier:
    """
    Dispatches incident packets to Telegram channels or webhooks.
    Formatted cleanly without decorative emojis.
    """

    def __init__(self, bot_token: Optional[str] = None, chat_id: Optional[str] = None, enabled: bool = True):
        self.bot_token = os.environ.get("SENTINEL_TELEGRAM_BOT_TOKEN") or bot_token or ""
        self.chat_id = os.environ.get("SENTINEL_TELEGRAM_CHAT_ID") or chat_id or ""
        self.enabled = enabled and bool(self.bot_token and self.chat_id)

    def format_incident_message(self, packet: IncidentPacket) -> str:
        telemetry = packet.host_telemetry
        top_proc_lines = []
        for p in telemetry.top_processes[:3]:
            top_proc_lines.append(f"  - {p['name']} (PID {p['pid']}): RAM {p['memory_percent']}%, CPU {p['cpu_percent']}%")
        procs_str = "\n".join(top_proc_lines) if top_proc_lines else "  - None reported"

        oom_str = "\n".join([f"  - {ev}" for ev in telemetry.oom_events[:3]]) if telemetry.oom_events else "  - None"

        # Limit traceroute output lines in alert message
        trace_lines = [line.strip() for line in packet.traceroute_output.splitlines() if line.strip()][:5]
        trace_summary = "\n".join([f"  {line}" for line in trace_lines]) if trace_lines else "  No trace hops available"

        message = (
            f"[INCIDENT ALERT] TARGET FAILURE DETECTED\n"
            f"Target: {packet.target_name} ({packet.target_type.upper()})\n"
            f"Endpoint: {packet.endpoint}\n"
            f"Timestamp: {packet.timestamp}\n"
            f"Trigger: {packet.trigger_reason}\n\n"
            f"TRIAGE INVESTIGATION:\n"
            f"1. Path Traceroute:\n"
            f"{trace_summary}\n\n"
            f"2. DNS Resolution:\n"
            f"  {packet.dns_resolution}\n\n"
            f"3. Host Telemetry Snapshot:\n"
            f"  CPU: {telemetry.cpu_percent}% | RAM: {telemetry.memory_percent}% "
            f"({telemetry.memory_used_mb}MB / {telemetry.memory_total_mb}MB)\n"
            f"  Top Memory Processes:\n"
            f"{procs_str}\n"
            f"  Kernel Alerts:\n"
            f"{oom_str}\n\n"
            f"ROOT CAUSE HYPOTHESIS:\n"
            f"{packet.root_cause_hypothesis}"
        )
        return message

    def send_incident(self, packet: IncidentPacket) -> bool:
        message_text = self.format_incident_message(packet)

        if not self.enabled:
            logger.info("Telegram notification skipped (bot_token or chat_id not configured)")
            return False

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": message_text,
            "disable_web_page_preview": True,
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                if resp.status == 200:
                    logger.info(f"Telegram incident dispatched for {packet.target_name}")
                    return True
                else:
                    logger.warning(f"Telegram API response code: {resp.status}")
                    return False
        except Exception as exc:
            logger.error(f"Failed to dispatch Telegram incident: {str(exc)}")
            return False
