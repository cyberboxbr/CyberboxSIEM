# CyberboxSIEM — sigma-hq Rule Pack

High-fidelity detection rules modelled after the SigmaHQ community rule set,
validated against CyberboxSIEM's Sigma compiler and event schema.

## Coverage

| Rule | MITRE Technique | Severity |
|---|---|---|
| sysmon_lolbins_execution | T1218 | medium |
| sysmon_certutil_download | T1105, T1140 | high |
| sysmon_shadow_copy_deletion | T1490 | critical |
| sysmon_scheduled_task_creation | T1053.005 | high |
| sysmon_suspicious_rundll32 | T1218.011 | high |
| sysmon_whoami_recon | T1033, T1082 | medium |
| sysmon_net_user_creation | T1136.001 | high |
| sysmon_pass_the_hash | T1550.002 | critical |
| sysmon_lateral_movement_psexec | T1570, T1021.006 | high |
| sysmon_credential_dumping_lsass | T1003.001 | critical |
| sysmon_dll_search_order_hijack | T1574.001 | medium |
| sysmon_registry_run_keys | T1547.001 | high |
| sysmon_defense_evasion_process_injection | T1055 | high |
| sysmon_ntds_dit_access | T1003.003 | critical |
| sysmon_network_scan_tools | T1046 | medium |
| sysmon_suspicious_parent_child | T1059, T1055.012 | high |
| sysmon_ransomware_file_encryption | T1486 | critical |
| sysmon_c2_beacon_outbound | T1071, T1095 | high |
| sysmon_kerberoasting | T1558.003 | critical |
| sysmon_defense_tamper | T1562.001 | critical |
| sysmon_data_exfiltration | T1567.002 | high |

## Importing

Load via the API (run from the server):
```bash
curl -X POST http://localhost:8080/api/v1/rules/sync-dir \
  -H 'Content-Type: application/json' \
  -d '{"path": "/app/rules/sigma-hq"}'
```

Or load both bundled + sigma-hq in one call:
```bash
curl -X POST http://localhost:8080/api/v1/rules/sync-dir \
  -H 'Content-Type: application/json' \
  -d '{"path": "/app/rules"}'
```

## Refreshing from SigmaHQ

Run `scripts/sync-sigma-rules.sh` to pull the latest compatible rules
from the SigmaHQ GitHub repository.
