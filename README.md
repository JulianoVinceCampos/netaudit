<div align="center">

# 🔍 NetAudit

**Scanner Profissional de Portas TCP e Auditoria de Serviços**

[![CI](https://github.com/yourusername/netaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/netaudit/actions)
[![Python](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue)](https://pypi.org/project/netaudit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Dependências](https://img.shields.io/badge/dependências-zero-brightgreen)](pyproject.toml)
[![Plataformas](https://img.shields.io/badge/plataforma-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/yourusername/netaudit)

*Zero dependências externas · Saída orientada a auditoria · Roda em qualquer ambiente com Python 3.8+*

</div>

---

> ⚠️ **USO EXCLUSIVAMENTE AUTORIZADO.** O NetAudit é uma ferramenta profissional de segurança
> destinada ao uso em sistemas que você possui ou para os quais possui **autorização escrita explícita**
> para testar. Varreduras não autorizadas são ilegais na maioria das jurisdições.
> Consulte o [LICENSE](LICENSE) para o aviso legal completo.

---

## O que é o NetAudit?

O NetAudit é um scanner TCP de portas e serviços estruturado e somente leitura, construído
para engenheiros de segurança, pentesters e administradores de sistemas que conduzem
auditorias de rede autorizadas. Ele é projetado para produzir **evidências de qualidade
técnica** — achados estruturados, classificações de risco e recomendações acionáveis —
não apenas dados brutos de portas.

### Princípios de Design

| Princípio | Implementação |
|---|---|
| **Seguro por padrão** | Apenas TCP connect, sem raw sockets, semáforo de concorrência, rate limiting configurável |
| **Zero privilégios** | Não requer root/administrador em nenhuma plataforma |
| **Zero dependências** | Pura stdlib Python — funciona em ambientes com restrição de pacotes |
| **Orientado a evidências** | Cada achado cita nível de risco, detalhe técnico e referências (CVE, MITRE, CWE) |
| **Biblioteca + CLI** | Importável como pacote Python; utilizável em pipelines de automação |
| **Amigável ao CI** | Exit code 1 em achados CRÍTICOS; modo silencioso legível por máquina |

---

## Funcionalidades

### Varredura
- TCP connect scan com detecção de `open` / `closed` / `filtered`
- Medição de RTT (round-trip time) por porta aberta
- Concorrência configurável (até 500 threads), timeout e rate limiting
- Modo `--safe`: limita automaticamente threads e timeout, adiciona controle de taxa

### Fingerprinting e Banner Grabbing
- **SSH** — captura do banner bruto (`SSH-2.0-OpenSSH_9.x`)
- **SMTP / FTP / POP3 / IMAP** — captura do greeting espontâneo
- **HTTP / HTTP-Alt** — probe `HEAD /`, captura header `Server` e linha de status
- **HTTPS / SMTPS / LDAPS / etc.** — handshake TLS + probe HTTP
- **Inspeção de Certificado TLS** — subject, issuer, lista de SANs, validade, detecção de auto-assinado, algoritmo de assinatura

### Motor de Achados (10 Categorias de Regras)

| Risco | Exemplos |
|---|---|
| 🔴 **Crítico** | Docker API sem TLS (2375), Telnet, X11, etcd, Kubelet read-only |
| 🟠 **Alto** | RDP, SSH, SMB, VNC, Redis, Elasticsearch, MongoDB, Memcached, certificado TLS expirado |
| 🟡 **Médio** | Protocolos plaintext (HTTP/FTP/LDAP/POP3/IMAP), certificado auto-assinado, interfaces de gerenciamento |
| 🔵 **Baixo / Info** | Versão exposta no banner, reminder de relay SMTP aberto |

### Formatos de Saída
- **Terminal** — relatório ANSI colorido com tabela de portas, resumo TLS e achados
- **JSON** — estruturado, adequado para ingestão em SIEM ou processamento adicional
- **CSV** — uma linha por porta, todos os campos, pronto para planilhas
- **Markdown** — relatório formatado pronto para GitHub, Confluence ou Notion

---

## Instalação

### Recomendado: Ambiente Virtual

```bash
git clone https://github.com/yourusername/netaudit.git
cd netaudit

# Criar e ativar o virtualenv
python3 -m venv venv
source venv/bin/activate           # Linux / macOS
.\venv\Scripts\Activate.ps1        # Windows PowerShell

# Instalar em modo editável (para desenvolvimento)
pip install -e ".[dev]"

# Ou instalar normalmente
pip install -e .
```

### Sem instalação (execução direta)

```bash
git clone https://github.com/yourusername/netaudit.git
cd netaudit
python -m netaudit 127.0.0.1 --banners
```

### Verificar instalação

```bash
python -m netaudit --version
python -m netaudit --selftest
```

---

## Início Rápido

```bash
# Escanear localhost — portas comuns com fingerprinting completo
python -m netaudit 127.0.0.1 --banners

# Escanear um host específico — top ports, modo seguro, todas as saídas
python -m netaudit 192.168.1.10 -p 1-1024 --safe --banners --out ./relatorios

# Conjunto de portas customizado + relatório markdown
python -m netaudit db.interno -p 3306,5432,6379,27017 --banners --out ./relatorios
```

---

## Referência de Uso

```
uso: netaudit [-h] [-p SPEC] [-t N] [--timeout SEC] [--banners] [--rdns]
              [--safe] [--out DIR] [--json FILE] [--csv FILE] [--md FILE]
              [--no-color] [-q] [-v] [--selftest] [--version]
              [target]
```

### Seleção de Portas

| Flag | Padrão | Descrição |
|---|---|---|
| `-p / --ports SPEC` | Portas comuns de alto risco | `22,80,443` · `1-1024` · `1-1024,8080,8443` |

### Comportamento da Varredura

| Flag | Padrão | Descrição |
|---|---|---|
| `-t / --threads N` | 50 | Máximo de conexões TCP simultâneas |
| `--timeout SEC` | 2.0 | Timeout de conexão TCP por porta (segundos) |
| `--banners` | desligado | Ativa banner grabbing + inspeção TLS |
| `--rdns` | desligado | Reverse DNS no IP resolvido |
| `--safe` | desligado | Reduz para 10 threads, timeout de 3s, rate limit de 20 req/s |

### Saída

| Flag | Descrição |
|---|---|
| `--out DIR` | Grava `JSON` + `CSV` + `Markdown` no diretório (nomes com timestamp) |
| `--json FILE` | Grava JSON em um caminho específico |
| `--csv FILE` | Grava CSV em um caminho específico |
| `--md FILE` | Grava Markdown em um caminho específico |
| `--no-color` | Desativa códigos ANSI |
| `-q / --quiet` | Modo legível por máquina: imprime apenas portas abertas como `porta/status/serviço/rtt` |
| `-v / --verbose` | Log com nível DEBUG e timestamps |

---

## Exemplo de Saída no Terminal

```
══════════════════════════════════════════════════════════════════════
  NetAudit v2.0.0 — TCP Port & Service Audit Report
══════════════════════════════════════════════════════════════════════
  Target       : 192.168.1.10
  Resolved IP  : 192.168.1.10
  Ports scanned: 71
  Scan started : 2025-01-15 14:32:01
  Banners      : enabled
══════════════════════════════════════════════════════════════════════

  OPEN PORTS (5 found)
  ────────────────────────────────────────────────────────────────────
  PORT    PROTO  SERVICE                RTT ms    BANNER / SERVER
  ────────────────────────────────────────────────────────────────────
⛔ 2375    tcp    Docker-API (unencrypt  1.2       {"Version":"24.0.5"}
⚠  22     tcp    SSH                    0.8       SSH-2.0-OpenSSH_9.2p
   80     tcp    HTTP                   0.5       HTTP/1.1 200 OK
   443    tcp    HTTPS                  2.1       HTTP/1.1 200 OK
   3306   tcp    MySQL/MariaDB          0.9       5.7.44-MySQL Community

  TLS / CERTIFICATE SUMMARY
  ────────────────────────────────────────────────────────────────────
  Port 443 HTTPS
    Subject   : CN=meuapp.exemplo.com
    Issuer    : CN=R3, O=Let's Encrypt, C=US
    Validity  : Valid (47d remaining)
    SANs      : DNS:meuapp.exemplo.com, DNS:www.meuapp.exemplo.com
    Sig Alg   : sha256WithRSAEncryption

  AUDIT FINDINGS & RECOMMENDATIONS
  ────────────────────────────────────────────────────────────────────

  [CRITICAL] Port 2375 — Docker API Exposed Without TLS
    The Docker daemon API (port 2375) is accessible without
    authentication or encryption. This is equivalent to
    unauthenticated root on the host...

    → Recommendation:
      Immediately bind Docker to a Unix socket (default). If remote
      access is required, enable TLS client certificates on port 2376.

  [HIGH    ] Port 22 — SSH Exposed to Network
    SSH (22) is accessible. While SSH is generally secure, broad
    exposure invites brute-force and credential-stuffing...

    → Recommendation:
      Restrict SSH access by IP via firewall. Disable password
      authentication. Disable root login. Use fail2ban.

══════════════════════════════════════════════════════════════════════
  Ports : 5 open  2 closed  64 filtered
  Findings: 1 CRITICAL · 2 HIGH · 1 MEDIUM
  Duration: 4.21s  |  Scanned: 71 ports
══════════════════════════════════════════════════════════════════════
```

---

## Exemplos Práticos

### 1. Auditoria completa do localhost com todas as saídas

```bash
python -m netaudit 127.0.0.1 \
  --banners \
  --rdns \
  --out ./relatorios/localhost
```

Gera:
- `relatorios/localhost/netaudit_127.0.0.1_20250115_143201.json`
- `relatorios/localhost/netaudit_127.0.0.1_20250115_143201.csv`
- `relatorios/localhost/netaudit_127.0.0.1_20250115_143201.md`

### 2. Varredura de range em modo seguro — pegada mínima na rede

```bash
python -m netaudit 10.0.0.1 \
  -p 1-1024 \
  --safe \
  --banners \
  --out ./relatorios
```

`--safe` limita para 10 conexões simultâneas e 20 req/s. Indicado para hosts em produção onde varreduras agressivas são proibidas pelo escopo do engagement.

### 3. Superfície de bancos de dados

```bash
python -m netaudit db-prod.interno \
  -p 1433,1521,3306,5432,6379,9042,27017,27018 \
  --banners \
  --timeout 3.0 \
  --out ./relatorios/auditoria-db
```

### 4. Integração com pipeline CI/CD

```bash
python -m netaudit staging.interno -p 1-1024 --banners --quiet
# Sai com código 0 se nenhum achado CRÍTICO, código 1 se houver
echo "Exit: $?"
```

### 5. Saída legível por máquina (para scripts)

```bash
python -m netaudit 192.168.1.1 -p 1-1024 --quiet 2>/dev/null
# Formato: porta/status/serviço/rtt/servidor
# 22/open/SSH/0.8ms/
# 80/open/HTTP/0.5ms/nginx
```

### 6. Uso como biblioteca Python

```python
from netaudit import Scanner, ScanConfig
from netaudit.utils import parse_ports
from netaudit.findings import analyse

config = ScanConfig(
    target="192.168.1.10",
    ports=parse_ports("22,80,443,3306,6379"),
    grab_banners=True,
    timeout=2.0,
    threads=25,
)

report = Scanner(config).run()
report.findings = analyse(report)

for finding in report.findings:
    print(f"[{finding.risk.value}] Porta {finding.port}: {finding.title}")

# Exportar
from netaudit.output import export_json, export_markdown
export_json(report, "relatorio.json")
export_markdown(report, "relatorio.md")
```

---

## Arquitetura do Projeto

```
netaudit/
├── netaudit/                    # Pacote principal
│   ├── __init__.py              # Superfície de API pública com __version__
│   ├── __main__.py              # Ponto de entrada CLI (python -m netaudit)
│   ├── constants.py             # Hints de porta, classificações de risco, conjuntos de protocolo
│   ├── models.py                # Dataclasses tipados (PortResult, ScanReport, Finding…)
│   ├── scanner.py               # ScanConfig + Scanner — engine TCP com concorrência
│   ├── fingerprint.py           # Banner grabbing, probe HTTP, inspeção TLS
│   ├── findings.py              # Motor de achados baseado em regras (10 categorias)
│   ├── output.py                # Renderizador de terminal, exportadores JSON/CSV/Markdown
│   ├── utils.py                 # Parser de portas, helpers DNS, safe_filename
│   └── tests/
│       ├── __init__.py
│       └── test_parsers.py      # Self-tests (via --selftest, sem rede)
│
├── tests/
│   └── test_all.py              # Suite pytest — models, findings, parsers, utilitários
│
├── .github/
│   ├── workflows/ci.yml         # CI: 5 versões Python × 3 OS + cobertura + lint + segurança
│   └── ISSUE_TEMPLATE/          # Template de bug report
│
├── pyproject.toml               # Empacotamento PEP 517/518, configuração ruff/mypy/pytest
├── CHANGELOG.md                 # Histórico de versões (Keep a Changelog)
├── CONTRIBUTING.md              # Guia de contribuição
├── SECURITY.md                  # Política de divulgação responsável
└── LICENSE                      # MIT + aviso de uso ético multilíngue
```

---

## Notas Técnicas

### Por que TCP Connect Scan?

O TCP connect scan completa o three-way handshake completo. Isso significa:

- ✅ **Não requer root/administrador** — o SYN scan com raw socket exige privilégios
- ✅ **Funciona em todas as plataformas** incluindo WSL, containers e VMs cloud restritas
- ✅ **Resultados confiáveis** — o OS gerencia retransmissões; `ConnectionRefused` é definitivo
- ⚠️ **Registrado pelo alvo** — a conexão aparece nos logs do servidor
- ⚠️ **Não é furtivo** — projetado para auditorias autorizadas, não para evasão red-team

### Definição dos Status de Porta

| Status | Comportamento TCP | Significado |
|---|---|---|
| `open` | Handshake completo | Serviço aceitando conexões |
| `closed` | `ConnectionRefused` / RST | Porta alcançável, nada escutando |
| `filtered` | Timeout / sem resposta | Firewall descartando pacotes — **não é o mesmo que fechado** |

**Importante:** `filtered` não significa seguro. Um firewall que descarta pacotes silenciosamente
do seu IP pode ainda permitir tráfego de outras origens. Valide as regras de firewall
a partir de múltiplas posições de rede.

### Limitações do Connect Scan

- Sem varredura UDP (requer raw sockets ou ferramentas como `nmap`)
- Sem fingerprinting de sistema operacional (requer criação de pacotes raw)
- Sem SYN scan furtivo (half-open)
- Um firewall stateful pode limitar conexões, inflando a contagem de `filtered`
- Banner grabbing é best-effort: serviços podem não responder sem input específico do protocolo

### Modo de Inspeção TLS

Os dados do certificado TLS são coletados em **modo auditoria** — a validação da cadeia
de certificados é intencionalmente desabilitada. Isso permite a inspeção de certificados
auto-assinados, expirados e de CAs internas sem erros. O NetAudit reporta metadados,
não valida confiança.

---

## Executando os Testes

```bash
# Suite pytest completa
pytest tests/ -v

# Com relatório de cobertura
pytest tests/ --cov=netaudit --cov-report=term-missing

# Sem rede, sem pytest — self-tests integrados
python -m netaudit --selftest

# Verificação de tipos
mypy netaudit/ --ignore-missing-imports

# Lint
ruff check netaudit/
```

---

## Checklist Pós-Varredura

Após executar uma varredura, percorra esta checklist:

**Inventário**
- [ ] Toda porta aberta tem uma justificativa de negócio documentada
- [ ] Portas inesperadas são investigadas antes de encerrar a avaliação

**Autenticação**
- [ ] SSH: apenas chave, login root desabilitado, fail2ban configurado
- [ ] RDP: NLA obrigatório, MFA habilitado, acesso restrito por IP
- [ ] Bancos de dados: autenticação habilitada, sem credenciais padrão/anônimas
- [ ] UIs de admin web: autenticação forte, restrição por IP, considerar acesso apenas via VPN

**Criptografia**
- [ ] Todos os certificados TLS são válidos e não auto-assinados
- [ ] Certificados têm validade ≥ 30 dias (automatizar renovação com ACME/Let's Encrypt)
- [ ] TLS 1.0/1.1 desabilitado — verificar com `testssl.sh --protocols <alvo>`
- [ ] HTTP redireciona para HTTPS com HSTS (`Strict-Transport-Security`)
- [ ] Protocolos plaintext (Telnet, FTP, LDAP, POP3, IMAP) substituídos por alternativas criptografadas

**Serviços de Alto Risco**
- [ ] Docker API (2375) fechado ou migrado para TLS-only (2376)
- [ ] Redis, Elasticsearch, MongoDB: autenticação habilitada, bind em localhost
- [ ] SMB com patch MS17-010 aplicado; SMBv1 desabilitado; signing obrigatório
- [ ] Memcached em bind localhost (vetor de DDoS por amplificação)

**Versão e Vulnerabilidades**
- [ ] Versões expostas nos banners cruzadas com NVD / bases de dados de CVE
- [ ] Varredura autenticada de vulnerabilidades executada nos serviços descobertos (OpenVAS, Nuclei, Trivy)

**Monitoramento**
- [ ] Alertas de falha de autenticação configurados para serviços expostos
- [ ] Log centralizado (SIEM) ingerindo logs dos serviços
- [ ] Re-varredura regular agendada (mínimo trimestral, mensal recomendado)

---

## Contribuindo

Consulte o [CONTRIBUTING.md](CONTRIBUTING.md) para:
- Configuração do ambiente de desenvolvimento
- Como adicionar novas regras de achados
- Estilo de código (ruff, mypy, docstrings)
- Processo de PR e formato de mensagem de commit

Para vulnerabilidades de segurança no próprio NetAudit, consulte o [SECURITY.md](SECURITY.md).

---

## Aviso Legal e Ético

O NetAudit é fornecido sob a [Licença MIT](LICENSE) com um requisito adicional de uso ético.
Você deve:

1. Ter **autorização escrita explícita** do proprietário do sistema antes de escanear.
2. Limitar sua varredura apenas aos alvos e faixas de porta acordados.
3. Tratar todos os achados como dados confidenciais em conformidade com as regras do seu engagement.

**Os autores não aceitam responsabilidade por uso indevido.** Acesso não autorizado a computadores
é crime. Legislações aplicáveis:

- 🇧🇷 Lei 12.737/2012 (Lei Carolina Dieckmann) e Art. 154-A do Código Penal
- 🇺🇸 Computer Fraud and Abuse Act (18 U.S.C. § 1030)
- 🇬🇧 Computer Misuse Act 1990
- 🇦🇺 Criminal Code Act 1995, Part 10.7
- 🇪🇺 Diretiva 2013/40/EU

---

<div align="center">

Feito para engenheiros de segurança que se importam com a qualidade das evidências.

</div>
