# Cyberbox Bundled Detection Rules

20 high-fidelity Sigma rules covering the agent's source types.

## Import

```bash
# Via API
curl -X POST http://localhost:3000/api/v1/rules/import-pack \
  -H "x-tenant-id: default" \
  -H "Content-Type: application/json" \
  -d '{"path": "rules/bundled"}'

# Via detection-as-code sync
CYBERBOX__RULES_DIR=rules/bundled cargo run --bin cyberbox-api
```

## Rule Coverage

| Source     | # Rules | MITRE Techniques                                    |
|------------|---------|-----------------------------------------------------|
| Sysmon     | 10      | T1003, T1055, T1059, T1071, T1547, T1574, T1559, T1014, T1546 |
| Procmon    | 5       | T1059, T1053, T1548, T1098, T1496                  |
| Docker     | 2       | T1610, T1611, T1059                                 |
| FIM        | 1       | T1543, T1556                                        |
| Netconn    | 1       | T1571, T1048                                        |
| Aggregation| 1       | T1110                                               |
