# CyberboxSIEM — SAFEBOX Onboarding Guide

**Prepared by:** CyberboxSecurity
**Client:** SAFEBOX
**Date:** 2026-03-11

---

## Overview

This guide configures a secure, encrypted site-to-site VPN between SAFEBOX's network and CyberboxSIEM, and shows how to forward logs from all sources — servers, firewalls, and endpoints — through that tunnel.

All traffic travels over **WireGuard VPN only**. Nothing is exposed to the public internet.

```
SAFEBOX network
  └── OPNsense firewall (WireGuard client, IP 10.10.0.10)
        └── [Encrypted tunnel → 18.205.126.224:51820]
              └── CyberboxSIEM (WireGuard server, IP 10.10.0.1)
                    └── Collector → Detection engine → Alerts → SIEM dashboard
```

**Key IPs (once tunnel is up):**
- CyberboxSIEM collector: `10.10.0.1` — all logs go here
- SAFEBOX VPN endpoint: `10.10.0.10`

---

## Part 1 — Site-to-Site VPN (OPNsense WireGuard)

### 1.1 — Enable WireGuard

Go to **VPN → WireGuard → Settings** → check **Enable WireGuard** → Save.

### 1.2 — Create the Local Instance (your OPNsense side)

Go to **VPN → WireGuard → Local** → Add:

| Field | Value |
|---|---|
| Name | `cyberbox-tunnel` |
| Listen Port | `51820` |
| Tunnel Address | `10.10.0.10/32` |
| **Private Key** | `OAEFIB8A/51+x1thkBMRB2rUzS/sx4dz5v7/0gO0nFU=` |

> **Keep the private key secret. Do not share it.**

### 1.3 — Add the CyberboxSIEM Peer

Go to **VPN → WireGuard → Peers** → Add:

| Field | Value |
|---|---|
| Name | `cyberboxsiem` |
| Public Key | `75tzmi7npAZjX4GK2/pmiJjAL0h8nbT8MkqgMjoRPl8=` |
| Endpoint Address | `18.205.126.224` |
| Endpoint Port | `51820` |
| Allowed IPs | `10.10.0.1/32` |
| Keepalive Interval | `25` |

`Allowed IPs = 10.10.0.1/32` routes only traffic destined for the CyberboxSIEM collector through the tunnel — everything else continues to use your normal internet connection.

### 1.4 — Assign the Interface

1. **Interfaces → Assignments** → find the new WireGuard instance → assign it → Save
2. Enable the interface, description: `CYBERBOX`
3. Under the CYBERBOX interface settings: **Enable**, IPv4 = None (WireGuard manages addressing)

### 1.5 — Add a Static Route

**System → Routes → Configuration** → Add:

| Field | Value |
|---|---|
| Network | `10.10.0.0/24` |
| Gateway | CYBERBOX (WireGuard interface) |

This allows all your internal devices to reach `10.10.0.1` through the tunnel by routing via OPNsense.

### 1.6 — Firewall Rule — allow outbound to collector

**Firewall → Rules → LAN** → Add:

| Field | Value |
|---|---|
| Action | Pass |
| Direction | out |
| Protocol | TCP/UDP |
| Source | LAN net |
| Destination | `10.10.0.1` |
| Destination port | `514` (syslog UDP) and `601` (syslog TCP) |
| Description | Allow syslog to CyberboxSIEM |

### 1.7 — Verify the Tunnel

In OPNsense shell (**System → Shell**):
```sh
wg show
```

You should see the `cyberboxsiem` peer. After the first packet, `latest handshake` will show a recent timestamp.

Test connectivity:
```sh
ping 10.10.0.1
```

---

## Part 2 — Forwarding Firewall Logs (OPNsense)

**System → Settings → Logging → Remote** → Add:

| Field | Value |
|---|---|
| Enable | checked |
| Transport | UDP |
| Hostname | `10.10.0.1` |
| Port | `514` |
| Log Level | Informational |
| Facilities | Firewall, Auth, Security (or All) |

This forwards OPNsense firewall blocks, auth events, and DHCP logs to CyberboxSIEM in real time.

---

## Part 3 — Windows Server Log Forwarding

### Option A — CyberboxSIEM Agent (Recommended)

The agent runs as a Windows service, tailing Windows Event Log and Sysmon events and forwarding them over the VPN tunnel.

**Download:** [cyberbox-agent-windows-x86_64.exe](https://github.com/cyberboxbr/CyberboxSIEM/releases/latest/download/cyberbox-agent-windows-x86_64.exe)

**Step 1 — Create the config directory and file:**
```powershell
New-Item -ItemType Directory -Force -Path "C:\ProgramData\cyberbox"
```

Create `C:\ProgramData\cyberbox\agent.toml`:

```toml
# CyberboxSIEM collector (reachable via WireGuard VPN)
[collector]
host     = "10.10.0.1"
port     = 601
protocol = "syslog"
backoff_max_secs = 30
buffer_size = 10000

[agent]
tenant_id = "safebox"

# Windows Event Log — Security, System, Application
[[source]]
type     = "wineventlog"
channels = ["Security", "System", "Application"]

# Sysmon — uncomment if Sysmon is installed (recommended)
# [[source]]
# type = "sysmon"
```

**Step 2 — Install and start as a Windows service:**
```powershell
# Copy binary to program files
New-Item -ItemType Directory -Force -Path "C:\Program Files\Cyberbox"
Copy-Item .\cyberbox-agent-windows-x86_64.exe "C:\Program Files\Cyberbox\cyberbox-agent.exe"

# Create the service
sc.exe create CyberboxAgent `
  binPath= "`"C:\Program Files\Cyberbox\cyberbox-agent.exe`" run --config `"C:\ProgramData\cyberbox\agent.toml`"" `
  start= auto `
  DisplayName= "CyberboxSIEM Agent"

sc.exe start CyberboxAgent
```

**Step 3 — (Optional but recommended) Install Sysmon** for detailed process/network telemetry:
```powershell
# Download Sysmon + community config
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml
.\Sysmon\sysmon64.exe -accepteula -i sysmonconfig.xml
```

Then uncomment the `[[source]] type = "sysmon"` block in agent.toml and restart the service.

### Option B — NXLog Community Edition

Download from [nxlog.co](https://nxlog.co/products/nxlog-community-edition/download) and add to `nxlog.conf`:

```xml
<Input eventlog>
    Module im_msvistalog
    Query <QueryList><Query Id="0">
        <Select Path="Security">*</Select>
        <Select Path="System">*</Select>
        <Select Path="Application">*</Select>
    </Query></QueryList>
</Input>

<Output syslog_out>
    Module om_udp
    Host 10.10.0.1
    Port 514
    Exec to_syslog_bsd();
</Output>

<Route 1>
    Path eventlog => syslog_out
</Route>
```

Restart the NXLog service after saving.

---

## Part 4 — Linux Server Log Forwarding

### Option A — CyberboxSIEM Agent (Recommended)

```bash
# x86_64 servers
curl -Lo /usr/local/bin/cyberbox-agent \
  https://github.com/cyberboxbr/CyberboxSIEM/releases/latest/download/cyberbox-agent-linux-x86_64
chmod +x /usr/local/bin/cyberbox-agent

# ARM64 servers (Raspberry Pi, ARM-based)
curl -Lo /usr/local/bin/cyberbox-agent \
  https://github.com/cyberboxbr/CyberboxSIEM/releases/latest/download/cyberbox-agent-linux-aarch64
chmod +x /usr/local/bin/cyberbox-agent
```

Create `/etc/cyberbox/agent.toml`:

```toml
# CyberboxSIEM collector (reachable via WireGuard VPN)
[collector]
host     = "10.10.0.1"
port     = 601
protocol = "syslog"
backoff_max_secs = 30
buffer_size = 10000

[agent]
tenant_id = "safebox"

# Journald (systemd logs — auth, ssh, sudo, kernel, etc.)
[[source]]
type  = "journald"

# Auth and syslog files
[[source]]
type          = "file"
paths         = ["/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log"]
poll_ms       = 500
bookmark_path = "/var/lib/cyberbox/agent.bookmark.json"

# Process monitoring via /proc — uncomment to enable
# [[source]]
# type    = "procmon"
# poll_ms = 1000
```

Install as a systemd service:

```bash
sudo mkdir -p /etc/cyberbox /var/lib/cyberbox

sudo tee /etc/systemd/system/cyberbox-agent.service > /dev/null <<EOF
[Unit]
Description=CyberboxSIEM Agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/cyberbox-agent run --config /etc/cyberbox/agent.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now cyberbox-agent
sudo systemctl status cyberbox-agent
```

### Option B — rsyslog

Add to `/etc/rsyslog.d/cyberbox.conf`:

```
# UDP (fire-and-forget)
*.* @10.10.0.1:514

# TCP (reliable, recommended)
*.* @@10.10.0.1:601
```

```bash
sudo systemctl restart rsyslog
```

### Option C — syslog-ng

```
destination d_cyberbox {
    syslog("10.10.0.1" port(601) transport("tcp"));
};

log { source(s_src); destination(d_cyberbox); };
```

---

## Part 5 — Endpoint Agent

Deploy the same agent binary on workstations for visibility into process creation, network connections, and file changes.

**Windows endpoints** — same install steps as Part 3, with Sysmon enabled.

**Linux endpoints** — same install steps as Part 4, with `procmon` and `netconn` sources uncommented:

```toml
[[source]]
type    = "procmon"
poll_ms = 1000

[[source]]
type    = "netconn"
poll_ms = 5000
```

---

## Part 6 — Verify Log Ingestion

Once the tunnel is up and at least one source is sending, open the dashboard:

**URL:** `https://siem.cyberboxsecurity.com.br` *(VPN required — connect WireGuard first)*

Go to **Search → Raw search** and run `*` — events should appear within seconds.

Filter by source IP or hostname to confirm your specific devices are sending.

---

## Summary

| Source | Method | Collector address |
|---|---|---|
| OPNsense firewall | Remote syslog UDP | `10.10.0.1:514` |
| Windows servers/endpoints | CyberboxAgent (WEL + Sysmon) | `10.10.0.1:601` TCP |
| Linux servers/endpoints | CyberboxAgent (journald + file) | `10.10.0.1:601` TCP |
| Any device | rsyslog / syslog-ng / NXLog | `10.10.0.1:514` UDP or `601` TCP |

---

## Support

Contact CyberboxSecurity for:
- Dashboard credentials
- Additional WireGuard peers (more sites or users)
- Custom detection rules
- Sysmon configuration tuning
