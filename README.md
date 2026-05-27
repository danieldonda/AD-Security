# 🛡️ AD Security Suite

> **Script PowerShell unificado para Assessment completo de segurança no Active Directory**
> Inventário do AD, detecção de ataques clássicos, vetores de ransomware e auditoria de qualidade de senhas — tudo em um único script com menu interativo.

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)](https://microsoft.com/powershell)
[![Windows Server](https://img.shields.io/badge/Windows%20Server-2016%2B-lightgray?logo=windows)](https://microsoft.com)
[![DSInternals](https://img.shields.io/badge/DSInternals-required-orange)](https://github.com/MichaelGrafnetter/DSInternals)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org)
[![Hackers Hive](https://img.shields.io/badge/Hackers%20Hive-danieldonda.com-cyan)](https://hackershive.com.br)
[![License](https://img.shields.io/github/license/danieldonda/AD-Security)](https://github.com/danieldonda/AD-Security/blob/main/LICENSE)

---

## 📋 Índice

- [Visão Geral](#-visão-geral)
- [Módulos disponíveis](#-módulos-disponíveis)
- [Pré-Requisitos](#-pré-requisitos)
- [Instalação](#-instalação)
- [Configuração](#-configuração)
- [Como Usar](#-como-usar)
- [Módulo 1 — AD Security Assessment](#módulo-1--ad-security-assessment)
- [Módulo 2 — Ransomware Readiness Assessment](#módulo-2--ransomware-readiness-assessment)
- [Módulo 3/4/5 — Auditoria de Senhas](#módulo-345--auditoria-de-senhas)
- [Módulo 6/7 — Hash Generators](#módulo-67--hash-generators)
- [Ransomware Risk Score](#-ransomware-risk-score)
- [TTPs MITRE ATT&CK Cobertos](#-ttps-mitre-attck-cobertos)
- [Arquivos Gerados](#-arquivos-gerados)
- [Estrutura do Repositório](#-estrutura-do-repositório)
- [Ferramentas Recomendadas](#-ferramentas-recomendadas)
- [Aviso Legal](#-aviso-legal)
- [Autor](#-autor)

---

## 🔎 Visão Geral

**AD Security Suite** é a evolução do projeto [AD-Security](https://github.com/danieldonda/AD-Security). Todos os scripts foram unificados em um único arquivo PowerShell com menu interativo, acrescido de um novo módulo de **Ransomware Readiness Assessment** com score de risco automatizado.

```
  ██████╗ ██████╗     ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
  ██╔══██╗██╔══██╗    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
  ███████║██║  ██║    ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝
  ██╔══██║██║  ██║    ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝
  ██║  ██║██████╔╝    ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║
  ╚═╝  ╚═╝╚═════╝     ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝

  AD Security Suite v2.0  |  danieldonda.com  |  Hackers Hive
```

> ⚠️ **Uso exclusivamente autorizado.** Execute apenas em ambientes nos quais você possui permissão explícita para realizar testes de segurança.

---

## 🧩 Módulos disponíveis

```
  ╔══════════════════════════════════════════════════╗
  ║              MENU PRINCIPAL                      ║
  ╠══════════════════════════════════════════════════╣
  ║  [1] AD Security Assessment                      ║
  ║  [2] Ransomware Readiness Assessment             ║
  ╠══════════════════════════════════════════════════╣
  ║  [3] Auditoria de Senhas - Padrão (DSInternals)  ║
  ║  [4] Auditoria de Senhas - Dicionário            ║
  ║  [5] Auditoria de Senhas - HIBP                  ║
  ╠══════════════════════════════════════════════════╣
  ║  [6] Hash Generator - SHA1                       ║
  ║  [7] Hash Generator - NTLM                       ║
  ╠══════════════════════════════════════════════════╣
  ║  [8] Full Assessment (Módulos 1 + 2)             ║
  ╚══════════════════════════════════════════════════╝
```

| Módulo | Função | Requer DSInternals |
|---|---|---|
| **1 — AD Security Assessment** | Inventário completo + Golden Ticket, DCSync, Print Spooler | Não |
| **2 — Ransomware Readiness** | 8 checks anti-ransomware + Risk Score | Não |
| **3 — Password Audit Padrão** | Senhas em branco, duplicadas, LM hashes | Sim |
| **4 — Password Audit Dicionário** | Comparação com wordlist personalizada | Sim |
| **5 — Password Audit HIBP** | Comparação com base Have I Been Pwned (~30 GB) | Sim |
| **6 — Hash Generator SHA1** | Converte wordlist para hashes SHA-1 | Não |
| **7 — Hash Generator NTLM** | Converte wordlist para hashes NTLM | Sim |
| **8 — Full Assessment** | Executa módulos 1 e 2 em sequência + exporta tudo | Não |

---

## ✅ Pré-Requisitos

| Requisito | Versão mínima | Observação |
|---|---|---|
| Windows PowerShell | 5.1+ | ou PowerShell 7+ |
| Módulo ActiveDirectory | — | Incluído no RSAT ou no próprio DC |
| Módulo DSInternals | Última versão | Apenas para módulos 3, 4, 5 e 7 |
| Windows Server | 2016+ | Com função AD DS |
| Permissão de execução | Domain Admin | Execute diretamente no Domain Controller |
| WinRM habilitado | — | Para verificações remotas nos DCs (módulo 2) |
| Espaço em disco (HIBP) | ~30 GB | Apenas para módulo 5 |

---

## 📦 Instalação

### 1. Instalar o módulo ActiveDirectory

```powershell
# Em Windows Server
Install-WindowsFeature -Name RSAT-AD-PowerShell

# Em Windows 10/11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

### 2. Instalar o módulo DSInternals (módulos 3, 4, 5 e 7)

```powershell
# Instalar via PSGallery
Install-Module DSInternals -Force

# Confirmar a instalação
Get-Module -ListAvailable DSInternals
```

> 💡 Se o PSGallery não estiver configurado como repositório confiável:
>
> ```powershell
> Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
> ```

### 3. Clonar o repositório

```powershell
# Via Git
git clone https://github.com/danieldonda/AD-Security.git
cd AD-Security

# Ou baixe o ZIP diretamente:
# https://github.com/danieldonda/AD-Security/archive/refs/heads/main.zip
```

### 4. Liberar a política de execução

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

---

## ⚙️ Configuração

Antes de executar, abra o arquivo `ADSecuritySuite.ps1` e edite o bloco `$CONFIG` no topo:

```powershell
$CONFIG = @{
    # Pasta de saída para CSVs, TXTs e hashes
    OutputFolder = "C:\temp"

    # Nome ou IP do Domain Controller (usado nos módulos de auditoria de senha)
    Servidor     = "NOME-DO-SEU-DC"

    # Naming context do domínio
    Dominio      = "dc=DOMINIO,dc=LOCAL"

    # Wordlist para geração de hashes e auditoria de dicionário
    Wordlist     = "C:\temp\senhas-texto-puro.txt"

    # Arquivo de saída para hashes SHA-1
    SHA1Output   = "C:\temp\senhas-sha1.txt"

    # Arquivo de saída para hashes NTLM
    NTLMOutput   = "C:\temp\senhas-ntlm.txt"

    # Base HIBP NTLM local (~30 GB) para auditoria offline de senhas comprometidas
    HIBPFile     = "C:\hibp\pwnedpasswords_ntlm.txt"
}
```

**Como descobrir o Naming Context do seu domínio:**

```powershell
Get-ADDomain | Select-Object DistinguishedName
# Exemplo de saída: DC=empresa,DC=local
```

---

## 🚀 Como Usar

Execute no **Domain Controller** com uma conta de **Domain Admin**:

```powershell
.\ADSecuritySuite.ps1
```

O menu interativo será exibido. Navegue com os números ou letras indicados. Todos os relatórios são exportados automaticamente para `C:\temp\` (ou o caminho definido em `$CONFIG.OutputFolder`).

---

## Módulo 1 — AD Security Assessment

Coleta um inventário completo do ambiente e destaca pontos críticos de segurança.

**O que é verificado:**

- Nível funcional da floresta e nome do domínio
- Inventário de usuários, computadores, grupos, DCs e OUs
- Usuários com senha que nunca expira
- Usuários sem logon há mais de 180 dias e contas inativas
- Membros dos grupos `Domain Admins` e `Administrators`
- Contas com `SIDHistory` — risco de escalada de privilégios
- `AdminSDHolder` — contas protegidas pelo processo SDProp
- Conta `Guest` habilitada
- Política de senha padrão do domínio

**Destaques de ataques:**

| Ataque | O que é verificado |
|---|---|
| **Golden Ticket** | Data da última modificação da conta `krbtgt` |
| **DCSync** | Criptografia reversível habilitada na política de senha |
| **Print Spooler** | DCs com o serviço Spooler ativo + objetos com Kerberos Delegation |

```
  GOLDEN TICKET ATTACK
  krbtgt modificada em               : 15/08/2023 09:12:44

  DCSYNC ATTACK
  Criptografia reversível habilitada : False

  PRINT SPOOLER / KERBEROS DELEGATION
  Objetos com Kerberos Delegation    : 3
  DCs com Print Spooler habilitado   : 2
    → DC02.empresa.local
    → DC03.empresa.local
```

> 💡 A conta `krbtgt` deve ser redefinida periodicamente. Se a data exibida for antiga, recomenda-se rotação imediata da senha para invalidar tickets existentes.

---

## Módulo 2 — Ransomware Readiness Assessment

Verifica os vetores mais explorados por grupos de ransomware modernos como **LockBit**, **BlackCat/ALPHV** e **Conti** para comprometer ambientes Active Directory.

**8 checks executados:**

| # | Verificação | Ransomware relacionado | MITRE |
|---|---|---|---|
| 1 | SMBv1 habilitado nos DCs | WannaCry, NotPetya | T1021.002 |
| 2 | AS-REP Roasting — contas sem pré-autenticação Kerberos | LockBit, Conti | T1558.004 |
| 3 | Kerberoasting — contas de usuário com SPNs | BlackCat, Hive | T1558.003 |
| 4 | LAPS — implantação e computadores sem senha gerenciada | Lateral movement | T1078 |
| 5 | Grupos sensíveis — Backup, Account, Server e Print Operators | NTDS.dit dump | T1078.002 |
| 6 | WDigest Authentication — credenciais em plaintext no LSASS | Credential harvesting | T1003.001 |
| 7 | AD Recycle Bin — capacidade de recuperação pós-ataque | Destruição de objetos | T1485 |
| 8 | Protected Users Security Group — Domain Admins sem proteção | Pass-the-Hash | T1550.002 |

```
  [CHECK 1/8] SMBv1 nos Domain Controllers
    [OK] DC01.empresa.local — SMBv1 desabilitado
    [!]  DC02.empresa.local — SMBv1 HABILITADO

  [CHECK 2/8] AS-REP Roasting
    [!] 2 conta(s) vulnerável(is):
        → svc_backup
        → svc_monitoring

  [CHECK 6/8] WDigest Authentication
    [!] DC02.empresa.local — WDigest HABILITADO (plaintext na memória!)

  [CHECK 8/8] Protected Users Security Group
    [!] 3 Domain Admin(s) fora do grupo 'Protected Users':
        → admin.joao
        → admin.maria
        → svc_infraadm
```

---

## Módulo 3/4/5 — Auditoria de Senhas

Utiliza o módulo **DSInternals** para extrair e auditar os hashes de senha de todos os usuários do AD.

> ⚠️ Requer acesso de **DC Replication** — execute diretamente no Domain Controller com conta de Domain Admin.

### Opção 3 — Auditoria Padrão

Verifica problemas sem arquivos externos: senhas em branco, senhas duplicadas entre usuários, contas com flags problemáticas e hashes LM presentes (protocolo legado inseguro).

### Opção 4 — Auditoria com Dicionário

Compara os hashes do AD com senhas de uma wordlist personalizada (uma senha por linha).

```
# Formato do arquivo wordlist
Password123
Admin@2024
empresa2024
```

> 💡 Fontes recomendadas: [SecLists](https://github.com/danielmiessler/SecLists), RockYou, wordlists personalizadas com nome da empresa, anos e datas comemorativas.

### Opção 5 — Auditoria com HIBP

Compara os hashes NTLM do AD com a base offline do **Have I Been Pwned** — mais de **1 bilhão de hashes NTLM** de senhas comprometidas em vazamentos reais.

> ⚠️ Requer o arquivo HIBP (~30 GB) baixado previamente.

**Como baixar:**

```powershell
# Instalar o downloader oficial (.NET 6+ obrigatório)
dotnet tool install -g haveibeenpwned-downloader

# Criar pasta e iniciar o download
New-Item -ItemType Directory -Path "C:\hibp" -Force
cd C:\hibp
haveibeenpwned-downloader -n pwnedpasswords_ntlm

# Verificar o arquivo gerado (~30 GB)
Get-Item "C:\hibp\pwnedpasswords_ntlm.txt" | Select-Object Name, @{N="GB";E={[math]::Round($_.Length/1GB,2)}}
```

> 🕐 O download pode levar várias horas dependendo da sua conexão. O downloader suporta retomada automática em caso de interrupção.

---

## Módulo 6/7 — Hash Generators

Convertem wordlists em arquivos de hashes para uso em auditorias de segurança.

### Opção 6 — SHA1 Generator

Usa o **.NET Framework** para calcular hashes SHA-1 a partir de um arquivo de texto puro. Ideal para criar dicionários compatíveis com o Have I Been Pwned.

### Opção 7 — NTLM Generator

Usa o módulo **DSInternals** (`ConvertTo-NTHash`) para calcular hashes NTLM. Ideal para comparação direta com dumps do AD.

> 💡 Este repositório inclui o arquivo `senhas-texto-puro.txt` com as 50 senhas mais usadas no Brasil como ponto de partida.

---

## 📊 Ransomware Risk Score

Ao final do módulo 2, o script calcula um **score de risco consolidado** de 0 a 100:

| Critério | Peso | Nível |
|---|---|---|
| SMBv1 habilitado em DCs | +25 | 🔴 Crítico |
| LAPS não instalado | +20 | 🔴 Crítico |
| WDigest habilitado em DCs | +20 | 🔴 Crítico |
| AS-REP Roasting | +15 | 🟠 Alto |
| Kerberoasting | +15 | 🟠 Alto |
| Domain Admins sem Protected Users | +10 | 🟠 Alto |
| AD Recycle Bin desabilitado | +5 | 🟡 Médio |

```
  RANSOMWARE RISK SCORE
  Score: 75 / 100  —  Nível: CRÍTICO

    [CRITICO +25] SMBv1 habilitado em DCs
    [CRITICO +20] WDigest habilitado — credenciais em plaintext
    [ALTO    +15] Contas vulneráveis a AS-REP Roasting (2)
    [ALTO    +10] Domain Admins sem Protected Users (3)
    [MEDIO   +5 ] AD Recycle Bin desabilitado
```

| Score | Nível de Risco |
|---|---|
| 0 – 19 | 🟢 Baixo |
| 20 – 39 | 🟡 Médio |
| 40 – 59 | 🟠 Alto |
| 60 – 100 | 🔴 Crítico |

---

## 🎯 TTPs MITRE ATT&CK Cobertos

### Golden Ticket

| TTP | Descrição |
|---|---|
| T1558.001 | Forja de tickets Kerberos via hash da conta `krbtgt` |
| T1078 | Valid Accounts — uso de credenciais privilegiadas comprometidas |
| T1208 | Exploitation of Trusted Relationships — abuso da confiança Kerberos |

### DCSync

| TTP | Descrição |
|---|---|
| T1003.006 | DCSync — replicação maliciosa de credenciais do AD |
| T1003.001 | LSASS Memory — dump de credenciais da memória |
| T1098 | Account Manipulation |

### Print Spooler / Kerberos Delegation

| TTP | Descrição |
|---|---|
| T1547 | Abuso do serviço Print Spooler para forçar autenticação |
| T1558.003 | Kerberoasting — extração de hashes de service accounts |
| T1550.003 | Pass the Ticket |

### Ransomware Readiness

| TTP | Check | Grupo / Ransomware |
|---|---|---|
| T1021.002 | SMBv1 habilitado | WannaCry, NotPetya |
| T1558.004 | AS-REP Roasting | LockBit, Conti |
| T1558.003 | Kerberoasting | BlackCat, Hive |
| T1078 | LAPS ausente | Lateral movement universal |
| T1078.002 | Backup/Account Operators | NTDS.dit dump |
| T1003.001 | WDigest habilitado | Credential harvesting LSASS |
| T1485 | AD Recycle Bin desabilitado | Destruição de objetos |
| T1550.002 | Protected Users vazio | Pass-the-Hash |

---

## 📁 Arquivos Gerados

Todos os arquivos são exportados para `C:\temp\` (configurável em `$CONFIG.OutputFolder`):

| Arquivo | Módulo | Conteúdo |
|---|---|---|
| `ADSecAssessment-Overview.txt` | 1 | Relatório completo em texto |
| `ad-users-password-never-expire.csv` | 1 | Usuários com senha que nunca expira |
| `ad-users-disabled.csv` | 1 | Usuários desabilitados |
| `ad-users-no-logon-180d.csv` | 1 | Usuários sem logon em 180 dias |
| `ad-users-domain-admins.csv` | 1 | Membros do grupo Domain Admins |
| `ad-users-administrators.csv` | 1 | Membros do grupo Administrators |
| `ad-users-sidhistory.csv` | 1 | Usuários com SIDHistory |
| `ad-adminSDHolder.csv` | 1 | Contas protegidas pelo AdminSDHolder |
| `ad-kerberos-delegation.csv` | 1 | Objetos com Kerberos Delegation |
| `ad-users-inactive.csv` | 1 | Usuários inativos (180 dias) |
| `ad-printspooler-enabled.csv` | 1 | DCs com Print Spooler ativo |
| `ransom-smbv1.csv` | 2 | Status SMBv1 por DC |
| `ransom-asrep-roasting.csv` | 2 | Contas vulneráveis a AS-REP Roasting |
| `ransom-kerberoasting.csv` | 2 | Contas kerberoastáveis com SPNs |
| `ransom-sem-laps.csv` | 2 | Computadores sem LAPS configurado |
| `ransom-grupos-sensiveis.csv` | 2 | Membros de grupos sensíveis |
| `ransom-wdigest.csv` | 2 | Status WDigest por DC |
| `ransom-admins-sem-protecao.csv` | 2 | Domain Admins fora do Protected Users |
| `ransom-risk-score.csv` | 2 | Score consolidado de risco ransomware |
| `senhas-sha1.txt` | 6 | Wordlist convertida para hashes SHA-1 |
| `senhas-ntlm.txt` | 7 | Wordlist convertida para hashes NTLM |
| `ADSecuritySuite-Hashes.txt` | Todos | Hashes SHA-256 de integridade de todos os arquivos |

> 💡 Os arquivos CSV podem ser importados diretamente no **Power BI** ou **Excel** para criação de dashboards e relatórios visuais.

---

## 🗂️ Estrutura do Repositório

```
AD-Security/
│
├── ADSecuritySuite.ps1          # Script unificado — todos os módulos
├── senhas-texto-puro.txt        # As 50 senhas mais usadas no Brasil
└── README.md                    # Este arquivo
```

---

## 🛠️ Troubleshooting

**Erro: `ActiveDirectory module not found`**

```powershell
# Windows Server
Install-WindowsFeature -Name RSAT-AD-PowerShell

# Windows 10/11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

**Erro: `DSInternals module not found`**

```powershell
Install-Module DSInternals -Force -AllowClobber
Import-Module DSInternals
```

**Erro: `Access Denied` ao executar `Get-ADReplAccount`**

> A conta utilizada precisa de permissões de **DC Replication** no AD.
> Execute o script diretamente no Domain Controller com uma conta de Domain Admin.

**Verificações remotas dos DCs falham (módulo 2)**

```powershell
# Testar conectividade WinRM com o DC
Test-WSMan -ComputerName NOME-DO-DC

# Habilitar WinRM remotamente se necessário
Invoke-Command -ComputerName NOME-DO-DC -ScriptBlock { Enable-PSRemoting -Force }
```

**Erro: `haveibeenpwned-downloader` não reconhecido**

```powershell
# Adicionar o caminho das ferramentas .NET ao PATH
$env:PATH += ";$env:USERPROFILE\.dotnet\tools"

# Para tornar permanente
[System.Environment]::SetEnvironmentVariable("PATH", $env:PATH, "User")
```

---

## 🔗 Ferramentas Recomendadas

| Ferramenta | Descrição |
|---|---|
| [HashHunter-AD](https://github.com/danieldonda/HashHunter-ad) | Auditoria avançada de qualidade de senhas no AD com HIBP |
| [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) | Módulo PowerShell para análise interna do AD |
| [BloodHound](https://github.com/BloodHoundAD/BloodHound) | Mapeamento visual de caminhos de ataque no AD |
| [Mimikatz](https://github.com/gentilkiwi/mimikatz) | Ferramenta de referência para ataques Pass-the-Hash |
| [Impacket](https://github.com/SecureAuthCorp/impacket) | Implementações de protocolos MSRPC em Python |
| [NTDSXtract](https://github.com/csababarta/ntdsxtract) | Framework de análise do `ntds.dit` em Python |

---

## ⚖️ Aviso Legal

> Este script é destinado exclusivamente a **profissionais de segurança autorizados** para auditorias em ambientes nos quais possuem permissão explícita.
> O uso não autorizado em ambientes de terceiros é ilegal e viola leis de crimes cibernéticos.
> O autor não se responsabiliza por usos indevidos desta ferramenta.

---

## 👨‍💻 Autor

**Daniel Donda**
🌐 [danieldonda.com](https://danieldonda.com)
🎓 [Hackers Hive — Plataforma de Treinamento em Cybersegurança](https://hackershive.com.br)
📺 YouTube: [@danieldonda](https://youtube.com/@danieldonda)
🐙 GitHub: [github.com/danieldonda](https://github.com/danieldonda)

---

Feito com 🔐 por [Daniel Donda](https://danieldonda.com) · [Hackers Hive](https://hackershive.com.br)
