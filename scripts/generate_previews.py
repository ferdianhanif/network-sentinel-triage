"""
Generates crisp PNG previews of Sentinel CLI execution and Incident Triage Packet
using headless Playwright Chrome for the README documentation.
"""

import os
from pathlib import Path
from playwright.sync_api import sync_playwright

CLI_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {
    margin: 0;
    padding: 30px;
    background-color: #0d1117;
    font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
    display: flex;
    justify-content: center;
    align-items: center;
  }
  .window {
    width: 900px;
    background-color: #161b22;
    border-radius: 8px;
    border: 1px solid #30363d;
    box-shadow: 0 16px 36px rgba(0,0,0,0.6);
    overflow: hidden;
  }
  .header {
    background-color: #21262d;
    padding: 10px 16px;
    display: flex;
    align-items: center;
    border-bottom: 1px solid #30363d;
  }
  .dots {
    display: flex;
    gap: 8px;
  }
  .dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
  }
  .dot.red { background-color: #f85149; }
  .dot.yellow { background-color: #e3b341; }
  .dot.green { background-color: #2ea043; }
  .title {
    color: #8b949e;
    font-size: 13px;
    margin-left: 16px;
  }
  .body {
    padding: 20px;
    color: #c9d1d9;
    font-size: 13px;
    line-height: 1.5;
  }
  .cmd { color: #58a6ff; font-weight: bold; }
  .dim { color: #8b949e; }
  .green { color: #3fb950; font-weight: bold; }
  .yellow { color: #d29922; }
  .cyan { color: #39c5cf; }
  .white { color: #f0f6fc; }
  .bar { color: #30363d; }
</style>
</head>
<body>
<div class="window">
  <div class="header">
    <div class="dots">
      <div class="dot red"></div>
      <div class="dot yellow"></div>
      <div class="dot green"></div>
    </div>
    <div class="title">sentinel-daemon :: bash -- 900x520</div>
  </div>
  <div class="body">
    <div><span class="green">ferdian@prod-bastion</span>:<span class="cyan">/opt/network-sentinel</span>$ <span class="cmd">python3 sentinel.py --run-once</span></div>
    <div class="bar">=================================================================</div>
    <div class="white">SENTINEL :: Network Health Monitor & Autonomous Incident Triage</div>
    <div class="bar">=================================================================</div>
    <div class="dim">[INFO] Executing single probe cycle across all configured targets...</div>
    <div class="dim">2026-10-12 15:38:51 [INFO] TARGET [gateway-icmp] STATUS=HEALTHY LATENCY=1.0ms</div>
    <div class="dim">2026-10-12 15:38:51 [INFO] TARGET [upstream-dns-tcp] STATUS=HEALTHY LATENCY=8.12ms</div>
    <div class="dim">2026-10-12 15:38:52 [INFO] TARGET [public-web-http] STATUS=HEALTHY LATENCY=216.3ms</div>
    <div class="dim">2026-10-12 15:38:52 [INFO] TARGET [local-database-tcp] STATUS=HEALTHY LATENCY=24.47ms</div>
    <div class="bar">-----------------------------------------------------------------</div>
    <div class="white">TARGET                 STATUS       LATENCY      DETAILS</div>
    <div class="bar">-----------------------------------------------------------------</div>
    <div>gateway-icmp           <span class="green">HEALTHY</span>      1.0 ms       Healthy</div>
    <div>upstream-dns-tcp       <span class="green">HEALTHY</span>      8.12 ms      Healthy</div>
    <div>public-web-http        <span class="green">HEALTHY</span>      216.3 ms     Healthy</div>
    <div>local-database-tcp     <span class="green">HEALTHY</span>      24.47 ms     Healthy</div>
    <div class="bar">-----------------------------------------------------------------</div>
    <div class="dim">[INFO] Cycle complete. Evaluated 4 targets in 249.89ms. Exit code: 0</div>
    <br>
    <div><span class="green">ferdian@prod-bastion</span>:<span class="cyan">/opt/network-sentinel</span>$ <span class="cmd">systemctl status sentinel.service</span></div>
    <div>* sentinel.service - Sentinel Network Health Monitor and Autonomous Triage Daemon</div>
    <div>  Loaded: loaded (/etc/systemd/system/sentinel.service; enabled; vendor preset: enabled)</div>
    <div>  Active: <span class="green">active (running)</span> since Mon 2026-10-12 08:00:00 UTC; 7h ago</div>
    <div>  Main PID: 18241 (python3)</div>
    <div>  Tasks: 2 (limit: 4915)</div>
    <div>  Memory: 22.4M</div>
  </div>
</div>
</body>
</html>
"""

TRIAGE_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {
    margin: 0;
    padding: 30px;
    background-color: #0d1117;
    font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
    display: flex;
    justify-content: center;
    align-items: center;
  }
  .window {
    width: 900px;
    background-color: #161b22;
    border-radius: 8px;
    border: 1px solid #30363d;
    box-shadow: 0 16px 36px rgba(0,0,0,0.6);
    overflow: hidden;
  }
  .header {
    background-color: #21262d;
    padding: 10px 16px;
    display: flex;
    align-items: center;
    border-bottom: 1px solid #30363d;
  }
  .dots {
    display: flex;
    gap: 8px;
  }
  .dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
  }
  .dot.red { background-color: #f85149; }
  .dot.yellow { background-color: #e3b341; }
  .dot.green { background-color: #2ea043; }
  .title {
    color: #8b949e;
    font-size: 13px;
    margin-left: 16px;
  }
  .body {
    padding: 20px;
    color: #c9d1d9;
    font-size: 13px;
    line-height: 1.5;
  }
  .badge-danger {
    background-color: rgba(248, 81, 73, 0.15);
    color: #f85149;
    padding: 2px 8px;
    border-radius: 4px;
    border: 1px solid rgba(248, 81, 73, 0.4);
    font-weight: bold;
  }
  .section-title {
    color: #58a6ff;
    font-weight: bold;
    margin-top: 14px;
    margin-bottom: 4px;
  }
  .hypothesis-box {
    background-color: #1f242c;
    border-left: 3px solid #f85149;
    padding: 10px 14px;
    margin-top: 10px;
    color: #f0f6fc;
  }
  .dim { color: #8b949e; }
  .white { color: #f0f6fc; }
  .green { color: #3fb950; }
  .yellow { color: #d29922; }
</style>
</head>
<body>
<div class="window">
  <div class="header">
    <div class="dots">
      <div class="dot red"></div>
      <div class="dot yellow"></div>
      <div class="dot green"></div>
    </div>
    <div class="title">sentinel-incident-triage-packet :: payload snapshot</div>
  </div>
  <div class="body">
    <div><span class="badge-danger">[INCIDENT ALERT] TARGET FAILURE DETECTED</span></div>
    <div style="margin-top: 8px;">Target: <span class="white">local-database-tcp (TCP)</span></div>
    <div>Endpoint: <span class="white">TCP://127.0.0.1:5432</span></div>
    <div>Timestamp: <span class="dim">2026-10-12T08:38:29Z</span></div>
    <div>Trigger: <span class="yellow">Threshold 2 consecutive failures reached (TCP connect refused)</span></div>

    <div class="section-title">TRIAGE INVESTIGATION (FREEZE-FRAME AT FAILURE T+0s):</div>
    <div>1. Path Traceroute:</div>
    <div class="dim">   Hop 1: 127.0.0.1 (&lt;1ms) - Loopback interface responsive</div>
    <div class="dim">   Status: Route path mapped. Local network interface online.</div>

    <div style="margin-top: 8px;">2. DNS Resolution:</div>
    <div class="dim">   Target 127.0.0.1 is a direct IP address. DNS lookup bypassed.</div>

    <div style="margin-top: 8px;">3. Host Telemetry Snapshot:</div>
    <div>   CPU: <span class="white">36.4%</span> | RAM: <span class="yellow">74.0%</span> (11.9 GB / 16.1 GB)</div>
    <div>   Top Memory Processes:</div>
    <div class="dim">   - MemCompression (PID 3460): RAM 5.3%, CPU 0.0%</div>
    <div class="dim">   - postgres-worker (PID 1420): RAM 4.2%, CPU 1.1%</div>
    <div class="dim">   - nginx-worker (PID 882): RAM 2.1%, CPU 0.2%</div>
    <div>   Kernel Alerts:</div>
    <div class="dim">   - No kernel OOM events detected in recent buffer.</div>

    <div class="section-title">ROOT CAUSE HYPOTHESIS:</div>
    <div class="hypothesis-box">
      Network route and host operating system are healthy. Failure is isolated to target port 5432: PostgreSQL service daemon stopped or rejected socket binding.
    </div>
  </div>
</div>
</body>
</html>
"""


def generate():
    out_dir = Path("docs/previews")
    out_dir.mkdir(parents=True, exist_ok=True)

    cli_path = out_dir / "cli_terminal_run.png"
    triage_path = out_dir / "incident_packet_triage.png"

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1000, "height": 700})

        # Render CLI preview
        page.set_content(CLI_HTML)
        page.wait_for_load_state("networkidle")
        page.screenshot(path=str(cli_path), full_page=True)
        print(f"Generated: {cli_path}")

        # Render Incident Triage preview
        page.set_content(TRIAGE_HTML)
        page.wait_for_load_state("networkidle")
        page.screenshot(path=str(triage_path), full_page=True)
        print(f"Generated: {triage_path}")

        browser.close()


if __name__ == "__main__":
    generate()
