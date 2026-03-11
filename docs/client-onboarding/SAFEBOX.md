# CyberboxSIEM — Guia de Integração SAFEBOX

**Preparado por:** CyberboxSecurity
**Cliente:** SAFEBOX
**Data:** 2026-03-11

---

## Visão Geral

Este guia configura uma VPN site-a-site segura e criptografada entre a rede da SAFEBOX e o CyberboxSIEM, e mostra como encaminhar logs de todas as fontes — servidores, firewalls e endpoints — através desse túnel.

Todo o tráfego trafega **exclusivamente pela VPN WireGuard**. Nada é exposto à internet pública.

```
Rede SAFEBOX
  └── Firewall OPNsense (cliente WireGuard, IP 10.10.0.10)
        └── [Túnel criptografado → 18.205.126.224:51820]
              └── CyberboxSIEM (servidor WireGuard, IP 10.10.0.1)
                    └── Coletor → Motor de detecção → Alertas → Dashboard SIEM
```

**IPs principais (após o túnel estar ativo):**
- Coletor CyberboxSIEM: `10.10.0.1` — todos os logs vão para cá
- Endpoint VPN da SAFEBOX: `10.10.0.10`

---

## Parte 1 — VPN Site-a-Site (OPNsense WireGuard)

### 1.1 — Habilitar o WireGuard

Acesse **VPN → WireGuard → Settings** → marque **Enable WireGuard** → Salvar.

### 1.2 — Criar a Instância Local (lado da SAFEBOX)

Acesse **VPN → WireGuard → Local** → Adicionar:

| Campo | Valor |
|---|---|
| Name | `cyberbox-tunnel` |
| Listen Port | `51820` |
| Tunnel Address | `10.10.0.10/32` |
| **Private Key** | `OAEFIB8A/51+x1thkBMRB2rUzS/sx4dz5v7/0gO0nFU=` |

> **Mantenha a chave privada em segredo. Não a compartilhe.**

### 1.3 — Adicionar o Peer CyberboxSIEM

Acesse **VPN → WireGuard → Peers** → Adicionar:

| Campo | Valor |
|---|---|
| Name | `cyberboxsiem` |
| Public Key | `75tzmi7npAZjX4GK2/pmiJjAL0h8nbT8MkqgMjoRPl8=` |
| Endpoint Address | `18.205.126.224` |
| Endpoint Port | `51820` |
| Allowed IPs | `10.10.0.1/32` |
| Keepalive Interval | `25` |

`Allowed IPs = 10.10.0.1/32` faz com que apenas o tráfego destinado ao coletor CyberboxSIEM passe pelo túnel — todo o restante continua usando sua conexão de internet normal.

### 1.4 — Atribuir a Interface

1. **Interfaces → Assignments** → localize a nova instância WireGuard → atribua → Salvar
2. Habilite a interface, descrição: `CYBERBOX`
3. Nas configurações da interface CYBERBOX: **Enable**, IPv4 = None (o WireGuard gerencia o endereçamento)

### 1.5 — Adicionar Rota Estática

**System → Routes → Configuration** → Adicionar:

| Campo | Valor |
|---|---|
| Network | `10.10.0.0/24` |
| Gateway | CYBERBOX (interface WireGuard) |

Isso permite que todos os dispositivos internos alcancem `10.10.0.1` através do túnel via OPNsense.

### 1.6 — Regra de Firewall — permitir syslog de saída

**Firewall → Rules → LAN** → Adicionar:

| Campo | Valor |
|---|---|
| Action | Pass |
| Direction | out |
| Protocol | TCP/UDP |
| Source | LAN net |
| Destination | `10.10.0.1` |
| Destination port | `514` (syslog UDP) e `601` (syslog TCP) |
| Description | Permitir syslog ao CyberboxSIEM |

### 1.7 — Verificar o Túnel

No shell do OPNsense (**System → Shell**):
```sh
wg show
```

Você deve ver o peer `cyberboxsiem` listado. Após o primeiro pacote, o campo `latest handshake` exibirá um timestamp recente.

Teste de conectividade:
```sh
ping 10.10.0.1
```

---

## Parte 2 — Encaminhamento de Logs do Firewall (OPNsense)

**System → Settings → Logging → Remote** → Adicionar:

| Campo | Valor |
|---|---|
| Enable | marcado |
| Transport | UDP |
| Hostname | `10.10.0.1` |
| Port | `514` |
| Log Level | Informational |
| Facilities | Firewall, Auth, Security (ou All) |

Isso encaminha em tempo real os bloqueios do firewall, eventos de autenticação e logs DHCP do OPNsense para o CyberboxSIEM.

---

## Parte 3 — Encaminhamento de Logs — Servidores Windows

### Opção A — Agente CyberboxSIEM (Recomendado)

O agente roda como serviço Windows, lendo o Windows Event Log e eventos do Sysmon e os encaminhando pelo túnel VPN.

**Download:** [cyberbox-agent-windows-x86_64.exe](https://github.com/cyberboxbr/CyberboxSIEM/releases/latest/download/cyberbox-agent-windows-x86_64.exe)

**Passo 1 — Criar o diretório e arquivo de configuração:**
```powershell
New-Item -ItemType Directory -Force -Path "C:\ProgramData\cyberbox"
```

Crie o arquivo `C:\ProgramData\cyberbox\agent.toml`:

```toml
# Coletor CyberboxSIEM (acessível via VPN WireGuard)
[collector]
host     = "10.10.0.1"
port     = 601
protocol = "syslog"
backoff_max_secs = 30
buffer_size = 10000

[agent]
tenant_id = "safebox"

# Windows Event Log — Segurança, Sistema, Aplicação
[[source]]
type     = "wineventlog"
channels = ["Security", "System", "Application"]

# Sysmon — descomente se o Sysmon estiver instalado (recomendado)
# [[source]]
# type = "sysmon"
```

**Passo 2 — Instalar e iniciar como serviço Windows:**
```powershell
# Copiar o binário para Arquivos de Programas
New-Item -ItemType Directory -Force -Path "C:\Program Files\Cyberbox"
Copy-Item .\cyberbox-agent-windows-x86_64.exe "C:\Program Files\Cyberbox\cyberbox-agent.exe"

# Criar o serviço
sc.exe create CyberboxAgent `
  binPath= "`"C:\Program Files\Cyberbox\cyberbox-agent.exe`" run --config `"C:\ProgramData\cyberbox\agent.toml`"" `
  start= auto `
  DisplayName= "CyberboxSIEM Agent"

sc.exe start CyberboxAgent
```

**Passo 3 — (Opcional, mas recomendado) Instalar o Sysmon** para telemetria detalhada de processos e rede:
```powershell
# Baixar Sysmon + configuração da comunidade
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml
.\Sysmon\sysmon64.exe -accepteula -i sysmonconfig.xml
```

Em seguida, descomente o bloco `[[source]] type = "sysmon"` no agent.toml e reinicie o serviço.

### Opção B — NXLog Community Edition

Baixe em [nxlog.co](https://nxlog.co/products/nxlog-community-edition/download) e adicione ao `nxlog.conf`:

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

Reinicie o serviço NXLog após salvar.

---

## Parte 4 — Encaminhamento de Logs — Servidores Linux

### Opção A — Agente CyberboxSIEM (Recomendado)

```bash
# Servidores x86_64
curl -Lo /usr/local/bin/cyberbox-agent \
  https://github.com/cyberboxbr/CyberboxSIEM/releases/latest/download/cyberbox-agent-linux-x86_64
chmod +x /usr/local/bin/cyberbox-agent

# Servidores ARM64 (Raspberry Pi, servidores ARM)
curl -Lo /usr/local/bin/cyberbox-agent \
  https://github.com/cyberboxbr/CyberboxSIEM/releases/latest/download/cyberbox-agent-linux-aarch64
chmod +x /usr/local/bin/cyberbox-agent
```

Crie o arquivo `/etc/cyberbox/agent.toml`:

```toml
# Coletor CyberboxSIEM (acessível via VPN WireGuard)
[collector]
host     = "10.10.0.1"
port     = 601
protocol = "syslog"
backoff_max_secs = 30
buffer_size = 10000

[agent]
tenant_id = "safebox"

# Journald (logs do systemd — auth, ssh, sudo, kernel, etc.)
[[source]]
type  = "journald"

# Arquivos de log de autenticação e sistema
[[source]]
type          = "file"
paths         = ["/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log"]
poll_ms       = 500
bookmark_path = "/var/lib/cyberbox/agent.bookmark.json"

# Monitoramento de processos via /proc — descomente para habilitar
# [[source]]
# type    = "procmon"
# poll_ms = 1000
```

Instalar como serviço systemd:

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

### Opção B — rsyslog

Adicione em `/etc/rsyslog.d/cyberbox.conf`:

```
# UDP (sem confirmação de entrega)
*.* @10.10.0.1:514

# TCP (confiável, recomendado)
*.* @@10.10.0.1:601
```

```bash
sudo systemctl restart rsyslog
```

### Opção C — syslog-ng

```
destination d_cyberbox {
    syslog("10.10.0.1" port(601) transport("tcp"));
};

log { source(s_src); destination(d_cyberbox); };
```

---

## Parte 5 — Agente em Endpoints

Instale o mesmo binário do agente nas estações de trabalho para visibilidade de criação de processos, conexões de rede e alterações de arquivos.

**Endpoints Windows** — mesmos passos da Parte 3, com Sysmon habilitado.

**Endpoints Linux** — mesmos passos da Parte 4, com as fontes `procmon` e `netconn` descomentadas:

```toml
[[source]]
type    = "procmon"
poll_ms = 1000

[[source]]
type    = "netconn"
poll_ms = 5000
```

---

## Parte 6 — Verificar a Ingestão de Logs

Com o túnel ativo e pelo menos uma fonte enviando, acesse o dashboard:

**URL:** `https://siem.cyberboxsecurity.com.br` *(requer VPN — conecte o WireGuard primeiro)*

Vá em **Search → Raw search** e execute `*` — os eventos devem aparecer em segundos.

Filtre por IP de origem ou hostname para confirmar que seus dispositivos específicos estão enviando.

---

## Resumo

| Fonte | Método | Endereço do coletor |
|---|---|---|
| Firewall OPNsense | Syslog remoto UDP | `10.10.0.1:514` |
| Servidores/endpoints Windows | CyberboxAgent (WEL + Sysmon) | `10.10.0.1:601` TCP |
| Servidores/endpoints Linux | CyberboxAgent (journald + arquivo) | `10.10.0.1:601` TCP |
| Qualquer dispositivo | rsyslog / syslog-ng / NXLog | `10.10.0.1:514` UDP ou `601` TCP |

---

## Suporte

Entre em contato com a CyberboxSecurity para:
- Credenciais de acesso ao dashboard
- Peers WireGuard adicionais (mais sites ou usuários)
- Regras de detecção personalizadas
- Ajuste de configuração do Sysmon
