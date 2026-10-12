#!/usr/bin/env python3
"""
Sentinel: Network and Host Health Daemon with Automated Incident Triage.
Autonomously freezes diagnostic telemetry (traceroute, DNS, host metrics)
at the moment of service failure.
"""

import argparse
import sys
import time
from pathlib import Path
from src.engine import SentinelEngine
from src.models import ProbeStatus


def print_banner() -> None:
    print("=" * 65)
    print("SENTINEL :: Network Health Monitor & Autonomous Incident Triage")
    print("=" * 65)


def handle_run_once(engine: SentinelEngine) -> int:
    print("[INFO] Executing single probe cycle across all configured targets...")
    results = engine.run_once()
    print("-" * 65)
    print(f"{'TARGET':<22} {'STATUS':<12} {'LATENCY':<12} {'DETAILS'}")
    print("-" * 65)

    has_down = False
    for r in results:
        status_str = r.status.value.upper()
        latency_str = f"{r.latency_ms} ms"
        detail_str = r.error if r.error else "Healthy"
        print(f"{r.target_name:<22} {status_str:<12} {latency_str:<12} {detail_str}")
        if r.status == ProbeStatus.DOWN:
            has_down = True

    print("-" * 65)
    print(f"[INFO] Cycle complete. Evaluated {len(results)} targets.")
    return 1 if has_down else 0


def handle_simulate(engine: SentinelEngine, target_name: str) -> int:
    print(f"[INFO] Triggering simulated failure on target: '{target_name}'...")
    try:
        incident = engine.simulate_triage(target_name)
    except ValueError as err:
        print(f"[ERROR] {str(err)}", file=sys.stderr)
        return 1

    msg = engine.notifier.format_incident_message(incident)
    print("\n" + "=" * 65)
    print("INCIDENT PACKET DISPATCH PREVIEW:")
    print("=" * 65)
    print(msg)
    print("=" * 65)
    print("[INFO] Incident logged to logs/incidents.jsonl successfully.")
    return 0


def handle_daemon(engine: SentinelEngine) -> int:
    print(f"[INFO] Starting Sentinel daemon (polling interval: {engine.interval_seconds}s)...")
    print("[INFO] Press Ctrl+C to terminate.")
    try:
        while True:
            engine.run_once()
            time.sleep(engine.interval_seconds)
    except KeyboardInterrupt:
        print("\n[INFO] Sentinel daemon stopped by user signal.")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sentinel Network Health Monitor & Autonomous Incident Triage"
    )
    parser.add_argument(
        "--config",
        default="config/targets.yaml",
        help="Path to YAML targets configuration file (default: config/targets.yaml)",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--run-once",
        action="store_true",
        help="Execute a single probing cycle and exit",
    )
    group.add_argument(
        "--daemon",
        action="store_true",
        help="Run continuously in background daemon loop",
    )
    group.add_argument(
        "--simulate-failure",
        metavar="TARGET_NAME",
        help="Force immediate triage packet generation for a target",
    )

    args = parser.parse_args()

    print_banner()

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"[ERROR] Configuration file not found: {cfg_path}", file=sys.stderr)
        return 1

    try:
        engine = SentinelEngine(config_path=str(cfg_path))
    except Exception as exc:
        print(f"[ERROR] Failed to initialize Sentinel engine: {str(exc)}", file=sys.stderr)
        return 1

    if args.simulate_failure:
        return handle_simulate(engine, args.simulate_failure)
    elif args.daemon:
        return handle_daemon(engine)
    else:
        # Default action: run-once
        return handle_run_once(engine)


if __name__ == "__main__":
    sys.exit(main())
