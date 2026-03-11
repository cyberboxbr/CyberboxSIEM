# CyberboxSIEM — Guia de Integração SAFEBOX

**Preparado por:** CyberboxSecurity
**Cliente:** SAFEBOX
**Data:** 2026-03-11
**Versão:** 1.0

---

## Visão Geral

Este guia configura uma VPN site-a-site segura e criptografada entre a rede da SAFEBOX e o CyberboxSIEM, e detalha como encaminhar logs de todas as fontes — servidores, firewalls e endpoints — através desse túnel criptografado.

**Todo o tráfego trafega exclusivamente pela VPN WireGuard. Nada é exposto à internet pública.**

```
Rede interna SAFEBOX (ex.: 192.168.1.0/24)
  └── Firewall OPNsense (cliente WireGuard — IP de túnel: 10.10.0.10)
        └── Túnel WireGuard criptografado (UDP 51820)
              └── 18.205.126.224 — CyberboxSIEM (servidor WireGuard — IP de túnel: 10.10.0.1)
                    ├── Coletor de logs (syslog UDP :514 / TCP :601)
                    ├── Motor de detecção (regras Sigma)
                    ├── Alertas em tempo real
                    └── Dashboard SIEM → https://siem.safebox.cyberboxsecurity.com.br
```

### IPs e portas importantes

| Recurso | Endereço | Protocolo |
|---|---|---|
| VPN Gateway (CyberboxSIEM) | `18.205.126.224:51820` | UDP WireGuard |
| IP do coletor na VPN | `10.10.0.1` | — |
| IP da SAFEBOX na VPN | `10.10.0.10` | — |
| Syslog UDP (dispositivos de rede) | `10.10.0.1:514` | UDP |
| Syslog TCP (agentes, rsyslog) | `10.10.0.1:601` | TCP |
| Dashboard SIEM | `https://siem.safebox.cyberboxsecurity.com.br` | HTTPS (via VPN) |

---

## Pré-requisitos

Antes de começar, confirme:

- [ ] OPNsense versão 23.x ou superior instalado
- [ ] Acesso de administrador ao OPNsense
- [ ] Acesso à internet no firewall (para estabelecer o túnel)
- [ ] Para Windows: domínio Active Directory (se for usar GPO)
- [ ] Para Windows: privilégios de Administrador local ou de Domínio
- [ ] Para Linux: acesso root ou sudo

---

## Parte 1 — VPN Site-a-Site (OPNsense WireGuard)

### 1.1 — Habilitar o WireGuard no OPNsense

1. No menu superior, acesse **VPN**
2. Clique em **WireGuard**
3. Clique em **Settings** (Configurações)
4. Marque a caixa **Enable WireGuard**
5. Clique em **Save** (Salvar)
6. Clique em **Apply changes** (Aplicar alterações) no topo da página

### 1.2 — Criar a Instância Local (identidade WireGuard da SAFEBOX)

Esta etapa cria o par de chaves e define o endereço IP da SAFEBOX dentro da VPN.

1. Acesse **VPN → WireGuard → Local**
2. Clique no botão **+** (Adicionar)
3. Preencha os campos conforme a tabela:

| Campo | Valor | Descrição |
|---|---|---|
| **Name** | `cyberbox-tunnel` | Nome identificador (somente para referência) |
| **Listen Port** | `51820` | Porta UDP onde o WireGuard escuta |
| **Tunnel Address** | `10.10.0.10/32` | IP da SAFEBOX dentro da VPN |
| **Private Key** | `OAEFIB8A/51+x1thkBMRB2rUzS/sx4dz5v7/0gO0nFU=` | Chave privada (pré-configurada) |
| **DNS Server** | *(deixar em branco)* | Não necessário para site-a-site |

4. Clique em **Save** → **Apply changes**

> ⚠️ **ATENÇÃO: A chave privada acima é exclusiva da SAFEBOX. Não a compartilhe com ninguém, nem a publique em nenhum sistema.**

### 1.3 — Adicionar o Peer CyberboxSIEM

Esta etapa registra o servidor CyberboxSIEM como peer de confiança.

1. Acesse **VPN → WireGuard → Peers**
2. Clique em **+** (Adicionar)
3. Preencha:

| Campo | Valor | Descrição |
|---|---|---|
| **Name** | `cyberboxsiem` | Nome identificador |
| **Enabled** | ✔ marcado | — |
| **Public Key** | `75tzmi7npAZjX4GK2/pmiJjAL0h8nbT8MkqgMjoRPl8=` | Chave pública do servidor CyberboxSIEM |
| **Endpoint Address** | `18.205.126.224` | IP público do servidor CyberboxSIEM |
| **Endpoint Port** | `51820` | Porta UDP do servidor |
| **Allowed IPs** | `10.10.0.1/32` | Apenas tráfego ao coletor passa pelo túnel |
| **Keepalive Interval** | `25` | Mantém o túnel ativo (em segundos) |

4. No campo **Instances**, selecione `cyberbox-tunnel` (criado no passo 1.2)
5. Clique em **Save** → **Apply changes**

> **O que é Allowed IPs?**
> Define quais destinos são roteados pelo túnel WireGuard. Usando `10.10.0.1/32`, apenas o tráfego de logs destinado ao coletor CyberboxSIEM passa pelo túnel. O tráfego de internet da SAFEBOX continua usando a conexão normal — sem impacto de desempenho.

### 1.4 — Atribuir a Interface WireGuard

1. Acesse **Interfaces → Assignments**
2. Na linha do novo dispositivo WireGuard (aparece como `wg0` ou similar), clique em **+** para atribuir
3. Clique em **Save**
4. Acesse a nova interface criada (aparecerá no menu como `OPT1` ou similar)
5. Preencha:
   - **Enable**: ✔ marcado
   - **Description**: `CYBERBOX`
   - **IPv4 Configuration Type**: `None` (o endereçamento é feito pelo WireGuard)
6. Clique em **Save** → **Apply changes**

### 1.5 — Adicionar Rota Estática

Para que os servidores internos da SAFEBOX possam alcançar `10.10.0.1` (o coletor), o OPNsense precisa saber que essa rede está acessível via o túnel WireGuard.

1. Acesse **System → Routes → Configuration**
2. Clique em **+** (Adicionar)
3. Preencha:

| Campo | Valor |
|---|---|
| **Network** | `10.10.0.0/24` |
| **Gateway** | Selecione a interface CYBERBOX (WireGuard) |
| **Description** | `Rota para coletor CyberboxSIEM` |

4. Clique em **Save** → **Apply changes**

### 1.6 — Regra de Firewall — permitir syslog de saída

Crie uma regra permitindo que os dispositivos internos enviem logs ao coletor.

1. Acesse **Firewall → Rules → LAN**
2. Clique em **+** (Adicionar)
3. Preencha:

| Campo | Valor |
|---|---|
| **Action** | `Pass` |
| **Direction** | `in` |
| **TCP/IP Version** | `IPv4` |
| **Protocol** | `TCP/UDP` |
| **Source** | `LAN net` |
| **Destination** | `Single host` → `10.10.0.1` |
| **Destination port range** | `514` a `514` (adicione outra regra para `601` a `601`) |
| **Description** | `Permitir syslog ao CyberboxSIEM` |

4. Clique em **Save** → **Apply changes**

> Crie duas regras: uma para porta 514 (UDP/syslog dispositivos) e outra para porta 601 (TCP/agentes).

### 1.7 — Verificar o Túnel

Acesse **System → Shell** e execute:

```sh
# Verificar status do WireGuard
wg show

# Saída esperada (após o primeiro handshake):
# interface: wg0
#   public key: <sua chave pública>
#   listening port: 51820
#
# peer: 75tzmi7npAZjX4GK2/pmiJjAL0h8nbT8MkqgMjoRPl8=
#   endpoint: 18.205.126.224:51820
#   allowed ips: 10.10.0.1/32
#   latest handshake: X seconds ago   ← deve aparecer após primeiro tráfego
#   transfer: X KiB received, X KiB sent
```

Teste de conectividade ao coletor:

```sh
ping -c 4 10.10.0.1
# Esperado: 4 pacotes enviados, 4 recebidos, 0% perda
```

Se o ping não funcionar, verifique:
- A regra de firewall na saída do OPNsense (Parte 1.6)
- Se o WireGuard está ativo (`wg show` deve listar o peer)
- Se a rota estática foi criada (Parte 1.5)

---

## Parte 2 — Encaminhamento de Logs do Firewall OPNsense

Esta é a configuração mais simples — o próprio OPNsense envia seus logs diretamente ao coletor.

1. Acesse **System → Settings → Logging**
2. Clique na aba **Remote**
3. Clique em **+** (Adicionar)
4. Preencha:

| Campo | Valor | Observação |
|---|---|---|
| **Enable** | ✔ marcado | |
| **Transport** | `UDP` | UDP 514 (padrão syslog) |
| **Hostname** | `10.10.0.1` | IP do coletor via VPN |
| **Port** | `514` | Porta syslog padrão |
| **Log Level** | `Informational` | Captura eventos normais e acima |
| **Facilities** | Selecione: `Security`, `Auth`, `Firewall` | Ou marque `All` para tudo |
| **Description** | `CyberboxSIEM` | |

5. Clique em **Save**

**O que será enviado:**
- Bloqueios e permissões do firewall (regras PF)
- Tentativas de autenticação SSH e GUI
- Eventos DHCP (concessões de IP)
- Alertas do sistema

**Verificação:** Após salvar, gere um evento (ex.: tente um login incorreto na GUI) e verifique no dashboard do SIEM em **Search** se o evento aparece.

---

## Parte 3 — Servidores Windows — Encaminhamento de Logs

Existem três abordagens. **Recomendamos o Agente CyberboxSIEM com instalação via GPO** para ambientes com Active Directory.

---

### Opção A — Agente CyberboxSIEM via GPO (Recomendado para domínios AD)

O agente é distribuído como **instalador MSI** compatível com Group Policy Object (GPO) do Windows, permitindo implantação silenciosa e centralizada em todos os computadores do domínio.

#### Pré-requisito: baixar o MSI

Baixe o instalador MSI na página de releases do projeto:

**[https://github.com/cyberboxbr/CyberboxSIEM/releases/latest](https://github.com/cyberboxbr/CyberboxSIEM/releases/latest)**

Arquivo: `cyberbox-agent-X.X.X.msi`

#### Etapa 1 — Criar o arquivo de configuração pré-configurado

O MSI instala um `agent.toml` padrão em `C:\ProgramData\Cyberbox\agent.toml`. Para que o agente já inicie com as configurações corretas da SAFEBOX, você tem duas opções:

**Opção 1 — GPO com Script de Inicialização (Recomendado)**

Crie o seguinte script PowerShell e salve como `Deploy-CyberboxAgent.ps1` em um compartilhamento de rede acessível por todos os computadores (ex.: `\\SEU-DC\netlogon\cyberbox\`):

```powershell
# Deploy-CyberboxAgent.ps1
# Script GPO de inicialização — implanta o agente CyberboxSIEM silenciosamente
# Colocar em: \\SEU-DC\netlogon\cyberbox\Deploy-CyberboxAgent.ps1

$ServiceName  = "CyberboxAgent"
$MsiPath      = "\\SEU-DC\netlogon\cyberbox\cyberbox-agent-windows.msi"
$ConfigDir    = "C:\ProgramData\Cyberbox"
$ConfigPath   = "$ConfigDir\agent.toml"
$LogPath      = "C:\Windows\Temp\cyberbox-deploy.log"

function Write-Log($msg) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp  $msg" | Out-File -Append -FilePath $LogPath
}

Write-Log "=== Deploy-CyberboxAgent iniciado ==="

# Verificar se o serviço já está instalado e em execução
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Log "Agente já instalado e em execução. Nenhuma ação necessária."
    exit 0
}

# Instalar MSI silenciosamente
Write-Log "Instalando MSI: $MsiPath"
$result = Start-Process msiexec.exe `
    -ArgumentList "/i `"$MsiPath`" /qn /norestart /l*v `"C:\Windows\Temp\cyberbox-msi.log`"" `
    -Wait -PassThru -NoNewWindow
if ($result.ExitCode -ne 0) {
    Write-Log "ERRO: msiexec retornou código $($result.ExitCode)"
    exit 1
}
Write-Log "MSI instalado com sucesso."

# Sobrescrever o agent.toml com configurações da SAFEBOX
Write-Log "Escrevendo configuração do agente..."
New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null

$Config = @"
# CyberboxSIEM Agent — SAFEBOX
# Gerado automaticamente via GPO. Não edite manualmente.

[collector]
host     = "10.10.0.1"
port     = 601
protocol = "syslog"
backoff_max_secs = 30
buffer_size = 10000

[agent]
tenant_id = "safebox"
hostname  = "$env:COMPUTERNAME"

# Windows Event Log
[[source]]
type     = "wineventlog"
channels = ["Security", "System", "Application"]

# Sysmon (descomente se o Sysmon estiver instalado)
# [[source]]
# type = "sysmon"
"@

Set-Content -Path $ConfigPath -Value $Config -Encoding UTF8
Write-Log "Configuração escrita em $ConfigPath"

# Reiniciar o serviço para aplicar a nova configuração
Write-Log "Reiniciando serviço CyberboxAgent..."
Restart-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Log "Serviço iniciado com sucesso."
} else {
    Write-Log "AVISO: Serviço pode não ter iniciado. Verifique o Event Viewer."
}

Write-Log "=== Deploy concluído ==="
```

#### Etapa 2 — Configurar o GPO no Active Directory

1. Abra o **Group Policy Management** no Domain Controller
2. Crie um novo GPO ou edite um existente que aplique a todos os computadores desejados:
   - Clique com o botão direito na OU desejada → **Create a GPO in this domain...**
   - Nome sugerido: `CyberboxSIEM Agent`
3. Clique com o botão direito no novo GPO → **Edit**
4. Navegue até:
   ```
   Computer Configuration
     └── Windows Settings
           └── Scripts (Startup/Shutdown)
                 └── Startup
   ```
5. Clique duas vezes em **Startup** → **Add**
6. Em **Script Name**, insira o caminho UNC do script:
   ```
   \\SEU-DC\netlogon\cyberbox\Deploy-CyberboxAgent.ps1
   ```
7. Clique em **OK** → **OK**
8. Certifique-se que o GPO está vinculado à OU correta

#### Etapa 3 — Permitir execução de scripts PowerShell via GPO

Para que o script seja executado, é necessário configurar a política de execução:

1. No mesmo GPO, navegue até:
   ```
   Computer Configuration
     └── Administrative Templates
           └── Windows Components
                 └── Windows PowerShell
                       └── Turn on Script Execution
   ```
2. Marque **Enabled**
3. Em **Execution Policy**, selecione **Allow all scripts** ou **Allow local scripts and remote signed scripts**
4. Clique em **OK**

#### Etapa 4 — Forçar atualização do GPO (opcional)

Para aplicar imediatamente sem aguardar o ciclo padrão (90 min):

```powershell
# Executar em cada máquina alvo ou via script remoto
gpupdate /force
```

#### Verificar instalação

Após reiniciar as máquinas (ou `gpupdate /force`), verifique em cada computador:

```powershell
# Verificar se o serviço está em execução
Get-Service CyberboxAgent

# Status esperado:
# Status   Name               DisplayName
# ------   ----               -----------
# Running  CyberboxAgent      Cyberbox SIEM Agent

# Ver os logs do agente no Event Viewer
Get-EventLog -LogName Application -Source CyberboxAgent -Newest 10

# Ver o log de instalação via GPO
Get-Content C:\Windows\Temp\cyberbox-deploy.log
```

---

### Opção B — Agente CyberboxSIEM — Instalação Manual

Para máquinas fora do domínio ou instalação individual.

**Download do instalador MSI:**
```
https://github.com/cyberboxbr/CyberboxSIEM/releases/latest/download/cyberbox-agent-windows.msi
```

**Ou download do executável standalone:**
```
https://github.com/cyberboxbr/CyberboxSIEM/releases/latest/download/cyberbox-agent-windows-x86_64.exe
```

**Passo 1 — Instalar o MSI:**
```powershell
# Instalação silenciosa
msiexec /i cyberbox-agent-windows.msi /qn

# Ou com log de instalação para diagnóstico
msiexec /i cyberbox-agent-windows.msi /qn /l*v C:\Temp\cyberbox-install.log
```

O MSI instala automaticamente:
- Binário em `C:\Program Files\Cyberbox\Agent\cyberbox-agent.exe`
- Config padrão em `C:\ProgramData\Cyberbox\agent.toml`
- Serviço Windows `CyberboxAgent` com inicialização automática

**Passo 2 — Editar a configuração:**

Abra `C:\ProgramData\Cyberbox\agent.toml` e substitua o conteúdo por:

```toml
# CyberboxSIEM Agent — SAFEBOX
[collector]
host     = "10.10.0.1"
port     = 601
protocol = "syslog"
backoff_max_secs = 30
buffer_size = 10000

[agent]
tenant_id = "safebox"

# Windows Event Log
[[source]]
type     = "wineventlog"
channels = ["Security", "System", "Application"]

# Sysmon — descomente se instalado (ver Parte 6)
# [[source]]
# type = "sysmon"
```

**Passo 3 — Reiniciar o serviço:**

```powershell
Restart-Service CyberboxAgent

# Verificar status
Get-Service CyberboxAgent
# Esperado: Running
```

---

### Opção C — NXLog Community Edition

Alternativa leve para ambientes sem necessidade do agente completo. Envia apenas eventos do Windows Event Log via syslog.

**Download:** [https://nxlog.co/products/nxlog-community-edition/download](https://nxlog.co/products/nxlog-community-edition/download)

Após instalar, edite `C:\Program Files (x86)\nxlog\conf\nxlog.conf`:

```xml
<!-- Definir diretório de dados -->
define ROOT C:\Program Files (x86)\nxlog

<Extension _syslog>
    Module xm_syslog
</Extension>

<!-- Coletar eventos de Segurança, Sistema e Aplicação -->
<Input eventlog>
    Module      im_msvistalog
    SavePos     TRUE
    ReadFromLast TRUE
    Query       <QueryList>
                  <Query Id="0">
                    <Select Path="Security">*</Select>
                    <Select Path="System">*</Select>
                    <Select Path="Application">*</Select>
                  </Query>
                </QueryList>
</Input>

<!-- Enviar para o coletor CyberboxSIEM via UDP syslog -->
<Output syslog_out>
    Module  om_udp
    Host    10.10.0.1
    Port    514
    Exec    to_syslog_bsd();
</Output>

<Route main>
    Path eventlog => syslog_out
</Route>
```

```powershell
# Reiniciar o serviço NXLog
Restart-Service nxlog
```

---

## Parte 4 — Servidores Linux — Encaminhamento de Logs

### Opção A — Agente CyberboxSIEM (Recomendado)

O agente é um binário estático (sem dependências) compatível com qualquer distribuição Linux.

#### Instalação

```bash
# Detectar arquitetura automaticamente e baixar o binário correto
ARCH=$(uname -m)
case $ARCH in
  x86_64)
    BINARY="cyberbox-agent-linux-x86_64"
    ;;
  aarch64|arm64)
    BINARY="cyberbox-agent-linux-aarch64"
    ;;
  *)
    echo "Arquitetura não suportada: $ARCH"
    exit 1
    ;;
esac

curl -fsSL \
  "https://github.com/cyberboxbr/CyberboxSIEM/releases/latest/download/${BINARY}" \
  -o /usr/local/bin/cyberbox-agent

chmod +x /usr/local/bin/cyberbox-agent

# Verificar
cyberbox-agent --version
```

#### Configuração

```bash
# Criar diretórios necessários
sudo mkdir -p /etc/cyberbox /var/lib/cyberbox
```

Crie o arquivo `/etc/cyberbox/agent.toml`:

```toml
# CyberboxSIEM Agent — SAFEBOX
[collector]
host     = "10.10.0.1"
port     = 601
protocol = "syslog"
backoff_max_secs = 30
buffer_size = 10000

[agent]
tenant_id = "safebox"

# Journald — captura todos os logs do systemd
# (SSH, sudo, cron, kernel, docker, aplicações, etc.)
[[source]]
type  = "journald"

# Arquivos de log tradicionais (para distros sem systemd)
[[source]]
type          = "file"
paths         = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/kern.log",
    "/var/log/secure",        # CentOS/RHEL
    "/var/log/messages",      # CentOS/RHEL
]
poll_ms       = 500
bookmark_path = "/var/lib/cyberbox/agent.bookmark.json"

# Monitoramento de processos — descomente para habilitar
# Monitora criação/encerramento de processos via /proc (zero dependências)
# [[source]]
# type    = "procmon"
# poll_ms = 1000

# Monitoramento de conexões de rede — descomente para habilitar
# Monitora conexões TCP abertas/fechadas via /proc/net/tcp
# [[source]]
# type    = "netconn"
# poll_ms = 5000
```

#### Instalar como serviço systemd

```bash
sudo tee /etc/systemd/system/cyberbox-agent.service > /dev/null << 'EOF'
[Unit]
Description=CyberboxSIEM Agent
Documentation=https://github.com/cyberboxbr/CyberboxSIEM
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cyberbox-agent run --config /etc/cyberbox/agent.toml
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cyberbox-agent

# Segurança: reduzir privilégios após inicialização
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

# Habilitar e iniciar
sudo systemctl daemon-reload
sudo systemctl enable cyberbox-agent
sudo systemctl start cyberbox-agent

# Verificar status
sudo systemctl status cyberbox-agent
```

#### Verificar que os logs estão sendo enviados

```bash
# Acompanhar os logs do agente em tempo real
sudo journalctl -u cyberbox-agent -f

# Verificar se há conexão com o coletor
ss -tn | grep 10.10.0.1
# Saída esperada: ESTAB  ... 10.10.0.1:601
```

---

### Opção B — rsyslog

Configuração nativa de syslog — sem instalação adicional. Disponível em todas as distribuições.

Crie o arquivo `/etc/rsyslog.d/50-cyberbox.conf`:

```
# Encaminhar todos os logs para o coletor CyberboxSIEM
# UDP — mais rápido, sem confirmação
*.* @10.10.0.1:514

# TCP — confiável, com confirmação de entrega (recomendado)
# Descomente a linha abaixo e comente a de cima para usar TCP
#*.* @@10.10.0.1:601
```

```bash
# Testar a configuração antes de reiniciar
sudo rsyslogd -N1

# Reiniciar rsyslog
sudo systemctl restart rsyslog

# Verificar se está funcionando
logger -t teste "Log de teste CyberboxSIEM — $(hostname)"
# Em seguida, verifique no dashboard se o evento apareceu
```

### Opção C — syslog-ng

Para servidores que utilizam syslog-ng ao invés de rsyslog.

Adicione ao arquivo de configuração (`/etc/syslog-ng/syslog-ng.conf` ou crie `/etc/syslog-ng/conf.d/cyberbox.conf`):

```
destination d_cyberbox_tcp {
    syslog(
        "10.10.0.1"
        port(601)
        transport("tcp")
        flush_lines(100)
        flush_timeout(1000)
    );
};

log {
    source(s_src);
    destination(d_cyberbox_tcp);
};
```

```bash
sudo systemctl restart syslog-ng
```

---

## Parte 5 — Dispositivos de Rede (Switches, Roteadores, APs)

A maioria dos dispositivos de rede suporta syslog nativo. Configure para enviar para:

- **Host:** `10.10.0.1`
- **Porta:** `514`
- **Protocolo:** `UDP`
- **Nível:** `Informational` ou superior

### Cisco IOS/IOS-XE
```
logging host 10.10.0.1
logging trap informational
logging on
```

### Cisco ASA / FTD
```
logging host inside 10.10.0.1
logging trap informational
logging enable
```

### Mikrotik RouterOS
```
/system logging action
add name=cyberbox target=remote remote=10.10.0.1 remote-port=514 bsd-syslog=yes
/system logging
add topics=firewall action=cyberbox
add topics=info action=cyberbox
```

### Ubiquiti UniFi
No Controller: **Settings → System → Remote Logging**
- Syslog Host: `10.10.0.1`
- Port: `514`

---

## Parte 6 — Sysmon (Windows) — Telemetria Avançada de Endpoints

O Sysmon da Microsoft captura eventos de segurança detalhados: criação de processos, conexões de rede, modificações no registro, carregamento de drivers, manipulação de memória e muito mais. **Fortemente recomendado em todos os endpoints e servidores Windows.**

### 6.1 — Instalação do Sysmon

```powershell
# Criar pasta temporária
New-Item -ItemType Directory -Force -Path C:\Temp\Sysmon

# Baixar Sysmon
Invoke-WebRequest `
  -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
  -OutFile "C:\Temp\Sysmon\Sysmon.zip"

# Extrair
Expand-Archive -Path "C:\Temp\Sysmon\Sysmon.zip" -DestinationPath "C:\Temp\Sysmon"

# Baixar configuração recomendada (SwiftOnSecurity — amplamente utilizada)
Invoke-WebRequest `
  -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
  -OutFile "C:\Temp\Sysmon\sysmonconfig.xml"

# Instalar com a configuração
C:\Temp\Sysmon\sysmon64.exe -accepteula -i C:\Temp\Sysmon\sysmonconfig.xml

# Verificar instalação
Get-Service Sysmon64
# Status esperado: Running
```

### 6.2 — Habilitar Sysmon no Agente CyberboxSIEM

Após instalar o Sysmon, edite `C:\ProgramData\Cyberbox\agent.toml` e descomente:

```toml
[[source]]
type = "sysmon"
```

Reinicie o serviço:
```powershell
Restart-Service CyberboxAgent
```

### 6.3 — Via GPO (para implantação em massa)

Adicione ao script `Deploy-CyberboxAgent.ps1` (Parte 3, Opção A):

```powershell
# --- Instalar Sysmon via GPO ---
$SysmonPath = "\\SEU-DC\netlogon\cyberbox\sysmon64.exe"
$SysmonConfig = "\\SEU-DC\netlogon\cyberbox\sysmonconfig.xml"

if (-not (Get-Service Sysmon64 -ErrorAction SilentlyContinue)) {
    Write-Log "Instalando Sysmon..."
    Start-Process $SysmonPath `
        -ArgumentList "-accepteula -i `"$SysmonConfig`"" `
        -Wait -NoNewWindow
    Write-Log "Sysmon instalado."
}
```

> Copie `sysmon64.exe` e `sysmonconfig.xml` para o mesmo compartilhamento de rede do MSI (`\\SEU-DC\netlogon\cyberbox\`).

### Eventos capturados pelo Sysmon

| ID | Evento | Técnica MITRE |
|---|---|---|
| 1 | Criação de processo | T1059 |
| 3 | Conexão de rede | T1071 |
| 5 | Encerramento de processo | — |
| 7 | Carregamento de imagem/DLL | T1574 |
| 8 | CreateRemoteThread | T1055 |
| 11 | Criação de arquivo | T1105 |
| 12/13 | Eventos de registro | T1547 |
| 22 | Consulta DNS | T1071.004 |
| 25 | Adulteração de processo | T1055 |

---

## Parte 7 — Verificação da Ingestão de Logs

### 7.1 — Acessar o Dashboard

1. **Conecte o WireGuard** (o túnel precisa estar ativo)
2. Acesse: **https://siem.safebox.cyberboxsecurity.com.br**
3. Faça login com as credenciais fornecidas pela CyberboxSecurity

### 7.2 — Confirmar que os logs estão chegando

No dashboard, vá em **Search** (Busca) e execute:

```
*
```

Você verá todos os eventos recentes. Para filtrar apenas os eventos da SAFEBOX:

```
tenant_id:safebox
```

Para filtrar por hostname específico:

```
hostname:NOME-DO-SERVIDOR
```

Para ver apenas eventos do firewall OPNsense:

```
hostname:opnsense
```

### 7.3 — Gerar eventos de teste

**Windows — forçar um evento de segurança:**
```powershell
# Tentativa de login falha (gera evento 4625 no Security Log)
$cred = New-Object System.Management.Automation.PSCredential("usuario-inexistente", (ConvertTo-SecureString "senha-errada" -AsPlainText -Force))
try { Start-Process cmd -Credential $cred -WindowStyle Hidden } catch {}
```

**Linux — gerar evento de autenticação:**
```bash
# Tentativa de SSH local com usuário inexistente
ssh usuario-inexistente@localhost 2>/dev/null || true
# Ou simplesmente
logger -t teste "Evento de teste SAFEBOX — $(date)"
```

**Firewall OPNsense:**
Tente acessar um IP bloqueado — o evento de bloqueio deve aparecer no SIEM.

---

## Parte 8 — Solução de Problemas

### O túnel WireGuard não conecta

```sh
# No OPNsense, verificar se WireGuard está ativo
wg show

# Verificar se a porta UDP 51820 está aberta no firewall
# (deve ter regra: pass in on $ext_if proto udp port 51820)

# Verificar conectividade com o servidor
ping 18.205.126.224
```

**Causas comuns:**
- A porta UDP 51820 está bloqueada no firewall de saída da SAFEBOX
- Chave pública ou privada incorreta — verifique a digitação

### Os logs não aparecem no SIEM

```sh
# Linux — verificar se o agente está conectado ao coletor
ss -tn | grep "10.10.0.1:601"

# Linux — ver logs do agente
sudo journalctl -u cyberbox-agent --since "5 minutes ago"

# Windows — verificar serviço
Get-Service CyberboxAgent
Get-EventLog -LogName Application -Source CyberboxAgent -Newest 20

# Testar conectividade manual ao coletor
# Linux:
nc -zv 10.10.0.1 601
# Esperado: "Connection to 10.10.0.1 601 port [tcp] succeeded"

# Windows:
Test-NetConnection -ComputerName 10.10.0.1 -Port 601
# Esperado: TcpTestSucceeded: True
```

**Causas comuns:**
- Túnel WireGuard inativo → verifique Parte 1.7
- Regra de firewall bloqueando a porta 601 → verifique Parte 1.6
- `agent.toml` com `host` incorreto → deve ser `10.10.0.1`
- `tenant_id` incorreto → deve ser `safebox`

### O agente não inicia no Windows

```powershell
# Ver erro detalhado
Get-EventLog -LogName System -Source "Service Control Manager" -Newest 20 |
  Where-Object { $_.Message -like "*Cyberbox*" }

# Ver log de instalação MSI
Get-Content C:\Windows\Temp\cyberbox-msi.log | Select-Object -Last 50
```

---

## Resumo — O que configurar

| Fonte | Método | Endereço do coletor |
|---|---|---|
| Firewall OPNsense | Syslog remoto UDP | `10.10.0.1:514` |
| Switches / Roteadores / APs | Syslog UDP nativo | `10.10.0.1:514` |
| Servidores Windows (domínio) | CyberboxAgent via GPO | `10.10.0.1:601` TCP |
| Servidores Windows (standalone) | CyberboxAgent MSI manual | `10.10.0.1:601` TCP |
| Servidores Linux | CyberboxAgent ou rsyslog | `10.10.0.1:601` TCP |
| Endpoints Windows | CyberboxAgent + Sysmon | `10.10.0.1:601` TCP |
| Endpoints Linux | CyberboxAgent + procmon | `10.10.0.1:601` TCP |

---

## Suporte

Entre em contato com a **CyberboxSecurity** para:

- Credenciais de acesso ao dashboard
- Peers WireGuard adicionais (mais sites, usuários remotos)
- Regras de detecção personalizadas para o ambiente SAFEBOX
- Configuração avançada do Sysmon
- Integração com outros sistemas (ITSM, ticketing, SOAR)
