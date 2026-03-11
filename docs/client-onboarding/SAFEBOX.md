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
  └── OPNsense (WireGuard)
        └── [Encrypted tunnel to 18.205.126.224:51820]
              └── CyberboxSIEM Collector
                    └── Detection engine → Alerts → SIEM dashboard
```

---

## Part 1 — Site-to-Site VPN (OPNsense WireGuard)

### 1.1 — Install WireGuard on OPNsense

OPNsense 23.x and later includes WireGuard natively.

1. Go to **VPN → WireGuard → Settings**
2. Enable WireGuard → Save

### 1.2 — Create the Local Instance (SAFEBOX side)

Go to **VPN → WireGuard → Local** → Add:

| Field | Value |
|---|---|
| Name | `cyberbox-tunnel` |
| Listen Port | `51820` (or any unused UDP port) |
| Tunnel Address | `10.10.0.10/32` |
| **Private Key** | `OAEFIB8A/51+x1thkBMRB2rUzS/sx4dz5v7/0gO0nFU=` |

> Keep the private key secret. Do not share it.

### 1.3 — Add the CyberboxSIEM Peer

Go to **VPN → WireGuard → Peers** → Add:

| Field | Value |
|---|---|
| Name | `cyberboxsiem` |
| Public Key | `75tzmi7npAZjX4GK2/pmiJjAL0h8nbT8MkqgMjoRPl8=` |
| Endpoint Address | `18.205.126.224` |
| Endpoint Port | `51820` |
| Allowed IPs | `10.10.0.1/32` |
| Keepalive | `25` |

**Allowed IPs `10.10.0.1/32`** means only traffic destined for the CyberboxSIEM collector IP goes through the tunnel.

### 1.4 — Assign the WireGuard Interface

1. Go to **Interfaces → Assignments** → assign the new WireGuard instance → Save
2. Enable the interface, set description: `CYBERBOX`
3. **Interfaces → CYBERBOX**: enable, no IP (tunnel handles it)

### 1.5 — Add a Static Route

Go to **System → Routes → Configuration** → Add:

| Field | Value |
|---|---|
| Network | `10.10.0.1/32` |
| Gateway | WireGuard interface |

This routes syslog traffic from your internal servers through the tunnel.

### 1.6 — Firewall Rule (allow outbound syslog)

Go to **Firewall → Rules → LAN** → Add:

| Field | Value |
|---|---|
| Action | Pass |
| Protocol | TCP/UDP |
| Source | LAN net |
| Destination | `10.10.0.1` |
| Destination port | `514` (UDP syslog), `601` (TCP syslog) |
| Description | Allow syslog to CyberboxSIEM |

### 1.7 — Verify the Tunnel

In OPNsense shell (**System → Shell**):
```sh
wg show
```

You should see `cyberboxsiem` peer listed. After the first traffic, `latest handshake` will appear.

---

## Part 2 — Forwarding Firewall Logs (OPNsense)

### 2.1 — Remote Syslog

Go to **System → Settings → Logging/Targets** → Add:

| Field | Value |
|---|---|
| Enable | checked |
| Transport | UDP |
| Hostname | `10.10.0.1` |
| Port | `514` |
| Level | Informational |
| Facilities | All (or: firewall, auth, security) |

This forwards OPNsense firewall, auth, and system logs to CyberboxSIEM in real time.

---

## Part 3 — Windows Server Log Forwarding

### Option A — CyberboxSIEM Agent (Recommended)

The agent is a lightweight binary that tails Windows Event Logs, Sysmon events, and forwards them directly over the VPN.

**Download:** Contact CyberboxSecurity for the Windows agent installer (`.msi`).

**Configuration** — create `C:\ProgramData\cyberbox\agent.toml`:

```toml
[collector]
url = "http://10.10.0.1:601"
batch_size = 500
flush_interval_ms = 5000

[sources.windows_event_log]
enabled = true
channels = ["Security", "System", "Application"]

[sources.sysmon]
enabled = true   # requires Sysmon installed

[disk_queue]
path = "C:\\ProgramData\\cyberbox\\queue"
max_bytes = 524288000   # 500 MB crash-safe buffer
```

**Install as a Windows service:**
```powershell
sc.exe create CyberboxAgent binPath= "C:\Program Files\Cyberbox\cyberbox-agent.exe --config C:\ProgramData\cyberbox\agent.toml" start= auto
sc.exe start CyberboxAgent
```

### Option B — NXLog Community Edition

Download from [nxlog.co](https://nxlog.co/products/nxlog-community-edition/download).

`nxlog.conf`:
```xml
<Extension json>
    Module xm_json
</Extension>

<Input eventlog>
    Module im_msvistalog
    Query <QueryList><Query Id="0"><Select Path="Security">*</Select><Select Path="System">*</Select></Query></QueryList>
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

### Option C — Windows Event Forwarding (WEF) + rsyslog forwarder

Suitable for environments with many servers. Contact CyberboxSecurity for WEC setup assistance.

---

## Part 4 — Linux Server Log Forwarding

### Option A — CyberboxSIEM Agent (Recommended)

```bash
# Install (replace with actual download URL from CyberboxSecurity)
curl -Lo cyberbox-agent.deb https://releases.cyberboxsecurity.com.br/agent/latest/cyberbox-agent_amd64.deb
sudo dpkg -i cyberbox-agent.deb
```

Config at `/etc/cyberbox/agent.toml`:

```toml
[collector]
url = "http://10.10.0.1:601"
batch_size = 500
flush_interval_ms = 5000

[sources.journald]
enabled = true

[sources.file]
enabled = true
paths = ["/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log"]

[sources.procmon]
enabled = true   # Linux process monitoring

[disk_queue]
path = "/var/lib/cyberbox/queue"
max_bytes = 524288000
```

```bash
sudo systemctl enable --now cyberbox-agent
```

### Option B — rsyslog

Add to `/etc/rsyslog.conf` or a file in `/etc/rsyslog.d/cyberbox.conf`:

```
# Forward all logs to CyberboxSIEM over UDP
*.* @10.10.0.1:514

# Or TCP (more reliable):
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

## Part 5 — Endpoint Agent (Windows/Linux workstations)

For endpoint visibility (process creation, network connections, file changes), deploy the CyberboxSIEM agent on each endpoint.

**Windows — with Sysmon (recommended):**

1. Install [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) with the [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config):
   ```powershell
   sysmon64.exe -accepteula -i sysmonconfig.xml
   ```

2. Install cyberbox-agent with Sysmon enabled in `agent.toml` (see Part 3, Option A).

**Linux — with procmon:**

Install the agent with `procmon.enabled = true` (see Part 4, Option A). This monitors all process creation events via `/proc`.

---

## Part 6 — Verify Log Ingestion

Once the VPN tunnel is up and at least one log source is sending, log into the CyberboxSIEM dashboard:

**URL:** `https://siem.cyberboxsecurity.com.br` (VPN required)

Go to **Search** and run:
```
*
```

You should see events arriving within seconds. Filter by your hostname or source IP to confirm your specific servers are sending.

---

## Summary — What to Configure

| Source | Method | Destination |
|---|---|---|
| OPNsense firewall | Remote syslog UDP | `10.10.0.1:514` |
| Windows servers | CyberboxAgent or NXLog | `10.10.0.1:601` TCP |
| Linux servers | CyberboxAgent or rsyslog | `10.10.0.1:514` UDP or `:601` TCP |
| Windows endpoints | CyberboxAgent + Sysmon | `10.10.0.1:601` TCP |
| Linux endpoints | CyberboxAgent + procmon | `10.10.0.1:601` TCP |

---

## Support

Contact CyberboxSecurity for:
- Agent installer downloads
- Dashboard access credentials
- Additional WireGuard peer configs (for more sites)
- Custom detection rules for your environment
