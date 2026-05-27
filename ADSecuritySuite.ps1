#Requires -Modules ActiveDirectory
#------------------------------------------------------------------------------------------------------------#
#  ___  ___  ___              _ _          ___      _ _
# / _ \|   \/ __| ___ __ _  _| (_)_ _ _  / __|_  _(_) |_ ___
#| (_) | |) \__ \/ -_) _| || | | | ' \  _\__ \ || | |  _/ -_)
# \___/|___/|___/\___\__|\___/|_|_|_||_(_)___/\_,_|_|\__\___|
#
# AD Security Suite v2.0 | danieldonda.com | Hackers Hive
#
# Módulos:
#   [1] AD Security Assessment     - Inventário e riscos críticos do AD
#   [2] Ransomware Readiness       - Vetores explorados por ransomware moderno
#   [3] Password Audit - Padrão    - Qualidade de senhas (DSInternals)
#   [4] Password Audit - Dicionário - Comparação com wordlist personalizada
#   [5] Password Audit - HIBP      - Comparação com base Have I Been Pwned
#   [6] Hash Generator - SHA1      - Gerador de hashes SHA-1 de wordlist
#   [7] Hash Generator - NTLM      - Gerador de hashes NTLM de wordlist
#   [8] Full Assessment            - Executa módulos 1 e 2 completos
#
# Autror  : Daniel Donda
# Website : https://danieldonda.com
# Curso   : https://hackershive.com.br
# Versão  : 2.0
# Nota    : Execute com credenciais administrativas no Domain Controller.
#           Uso exclusivamente autorizado.
#------------------------------------------------------------------------------------------------------------#

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# CONFIGURAÇÕES GLOBAIS
# ============================================================
$CONFIG = @{
    # Pasta de saída para CSVs, TXTs e hashes
    OutputFolder    = "C:\temp"

    # Servidor AD (nome do DC ou IP) — usado nos módulos de auditoria de senha
    Servidor        = "NOME-DO-SEU-DC"

    # Naming context do domínio (Get-ADDomain | Select DistinguishedName)
    Dominio         = "dc=DOMINIO,dc=LOCAL"

    # Wordlist para geração de hashes e auditoria de dicionário
    Wordlist        = "C:\temp\senhas-texto-puro.txt"

    # Arquivo de saída para hashes SHA-1
    SHA1Output      = "C:\temp\senhas-sha1.txt"

    # Arquivo de saída para hashes NTLM
    NTLMOutput      = "C:\temp\senhas-ntlm.txt"

    # Base HIBP NTLM local (~30 GB) para auditoria offline de senhas comprometidas
    HIBPFile        = "C:\hibp\pwnedpasswords_ntlm.txt"
}

# ============================================================
# FUNÇÕES AUXILIARES
# ============================================================

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ██████╗ ██████╗     ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗" -ForegroundColor Cyan
    Write-Host "  ██╔══██╗██╔══██╗    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝" -ForegroundColor Cyan
    Write-Host "  ███████║██║  ██║    ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝ " -ForegroundColor Cyan
    Write-Host "  ██╔══██║██║  ██║    ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝  " -ForegroundColor Cyan
    Write-Host "  ██║  ██║██████╔╝    ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║   " -ForegroundColor Cyan
    Write-Host "  ╚═╝  ╚═╝╚═════╝     ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   " -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ███████╗██╗   ██╗██╗████████╗███████╗" -ForegroundColor DarkCyan
    Write-Host "  ██╔════╝██║   ██║██║╚══██╔══╝██╔════╝" -ForegroundColor DarkCyan
    Write-Host "  ███████╗██║   ██║██║   ██║   █████╗  " -ForegroundColor DarkCyan
    Write-Host "  ╚════██║██║   ██║██║   ██║   ██╔══╝  " -ForegroundColor DarkCyan
    Write-Host "  ███████║╚██████╔╝██║   ██║   ███████╗" -ForegroundColor DarkCyan
    Write-Host "  ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  AD Security Suite v2.0  |  danieldonda.com  |  Hackers Hive" -ForegroundColor White
    Write-Host "  $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" -ForegroundColor DarkGray
    Write-Host ""
}

function Ensure-OutputFolder {
    if (!(Test-Path -Path $CONFIG.OutputFolder)) {
        New-Item -ItemType Directory -Path $CONFIG.OutputFolder | Out-Null
        Write-Host "  [+] Pasta de saída criada: $($CONFIG.OutputFolder)" -ForegroundColor Green
    }
}

function Write-Section {
    param([string]$Title, [string]$Color = "Yellow")
    Write-Host ""
    Write-Host "  ═══════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host "  $Title" -ForegroundColor $Color
    Write-Host "  ═══════════════════════════════════════════════════" -ForegroundColor DarkGray
}

function Write-Check {
    param([string]$Label, $Value, [string]$WarnColor = "Red")
    Write-Host ("  {0,-45}" -f "$Label`:") -ForegroundColor White -NoNewline
    Write-Host " $Value" -ForegroundColor $WarnColor
}

function Generate-FileHashes {
    Write-Host ""
    Write-Host "  [*] Gerando hashes de integridade dos arquivos..." -ForegroundColor DarkGray
    $hashFile = "$($CONFIG.OutputFolder)\ADSecuritySuite-Hashes.txt"
    "# Hashes de integridade - AD Security Suite - $(Get-Date)" | Set-Content $hashFile
    Get-ChildItem $CONFIG.OutputFolder -File | Where-Object { $_.Name -ne "ADSecuritySuite-Hashes.txt" } | ForEach-Object {
        $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        "$($_.Name) | SHA256: $hash" | Add-Content $hashFile
        Write-Host "  [✓] $($_.Name)" -ForegroundColor DarkGreen
    }
    Write-Host "  [+] Hashes salvos em: $hashFile" -ForegroundColor Green
}

function Show-MainMenu {
    Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
    Write-Host "  ║              MENU PRINCIPAL                      ║" -ForegroundColor DarkCyan
    Write-Host "  ╠══════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
    Write-Host "  ║  [1] AD Security Assessment                      ║" -ForegroundColor White
    Write-Host "  ║  [2] Ransomware Readiness Assessment             ║" -ForegroundColor White
    Write-Host "  ╠══════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
    Write-Host "  ║  [3] Auditoria de Senhas - Padrão (DSInternals)  ║" -ForegroundColor White
    Write-Host "  ║  [4] Auditoria de Senhas - Dicionário            ║" -ForegroundColor White
    Write-Host "  ║  [5] Auditoria de Senhas - HIBP (Have I Been Pwned) ║" -ForegroundColor White
    Write-Host "  ╠══════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
    Write-Host "  ║  [6] Hash Generator - SHA1 (wordlist → SHA1)     ║" -ForegroundColor White
    Write-Host "  ║  [7] Hash Generator - NTLM (wordlist → NTLM)     ║" -ForegroundColor White
    Write-Host "  ╠══════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
    Write-Host "  ║  [8] Full Assessment (Módulos 1 + 2)             ║" -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
    Write-Host "  ║  [Q] Sair                                        ║" -ForegroundColor DarkGray
    Write-Host "  ╚══════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
    Write-Host ""
}

# ============================================================
# MÓDULO 1 — AD SECURITY ASSESSMENT
# ============================================================
function Invoke-ADSecurityAssessment {

    Write-Section "MÓDULO 1 — AD SECURITY ASSESSMENT" "Yellow"

    Import-Module ActiveDirectory

    $date        = Get-Date
    $180daysAgo  = $date.AddDays(-180)

    # --- Coleta de informações do domínio ---
    $Domain                 = Get-ADDomain
    $Forest                 = Get-ADForest
    $DomainName             = $Domain.DNSRoot
    $ForestFunctionalLevel  = $Forest.ForestMode
    $UsersCount             = (Get-ADUser -Filter * -SearchBase $Domain.DistinguishedName).Count
    $ComputersCount         = (Get-ADComputer -Filter * -SearchBase $Domain.DistinguishedName).Count
    $GroupsCount            = (Get-ADGroup -Filter * -SearchBase $Domain.DistinguishedName).Count
    $domainControllers      = Get-ADDomainController -Filter *
    $OUsCount               = (Get-ADOrganizationalUnit -Filter * -SearchBase $Domain.DistinguishedName).Count

    # --- Contas ---
    $userspne        = Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties DisplayName,SamAccountName,PasswordLastSet
    $usersadmin      = Get-ADGroupMember -Identity "Domain Admins" -Recursive | Get-ADUser -Properties DisplayName,SamAccountName
    $usersadmin1     = Get-ADGroupMember -Identity "Administrators" -Recursive | Get-ADUser -Properties DisplayName,SamAccountName
    $usersdisabled   = Get-ADUser -Filter {Enabled -eq $false} -Properties DisplayName,SamAccountName,PasswordLastSet
    $users180dias    = Get-ADUser -Filter {LastLogonTimeStamp -lt $180daysAgo} -Properties DisplayName,SamAccountName,LastLogonTimeStamp
    $userssidhistory = Get-ADUser -LDAPFilter '(!sidhistory=*)' -Properties DisplayName,SamAccountName,sidhistory
    $AdminsdHolder   = Get-ADUser -Filter {admincount -gt 0} -Properties adminCount -ResultSetSize $null
    $Guest           = Get-ADUser -Filter {SamAccountName -eq "Guest"} -Properties Enabled
    $inativos        = Search-ADAccount -AccountInActive -UsersOnly -TimeSpan 180:00:00:00 -ResultPageSize 2000 -ResultSetSize $null | Where-Object {$_.Enabled -eq $True}

    # --- Política de senha ---
    $passPolicy = Get-ADDefaultDomainPasswordPolicy

    # --- Ataques ---
    $krbtgt        = Get-ADUser -Filter {samAccountName -eq "krbtgt"} -Properties WhenChanged
    $reversiblePwd = (Get-ADDefaultDomainPasswordPolicy).ReversibleEncryptionEnabled
    $kerbdelegation = Get-ADObject -Filter {
        (UserAccountControl -BAND 0x0080000) -OR
        (UserAccountControl -BAND 0x1000000) -OR
        (msDS-AllowedToDelegateTo -like '*')
    } -Properties Name,ObjectClass,UserAccountControl,ServicePrincipalName,msDS-AllowedToDelegateTo

    $spoolerEnabled = @(); $spoolerDisabled = @()
    foreach ($dc in $domainControllers) {
        $spooler = Get-Service -Name "Spooler" -ComputerName $dc.HostName -ErrorAction SilentlyContinue
        if ($spooler.Status -eq "Running") { $spoolerEnabled += $dc.HostName }
        else { $spoolerDisabled += $dc.HostName }
    }

    # --- Exibição ---
    Write-Section "RESUMO DO ACTIVE DIRECTORY" "Cyan"
    Write-Check "Nome do domínio"                   $DomainName             "Green"
    Write-Check "Nível funcional da floresta"        $ForestFunctionalLevel  "Green"
    Write-Check "Quantidade de usuários"             $UsersCount             "Green"
    Write-Check "Quantidade de computadores"         $ComputersCount         "Green"
    Write-Check "Quantidade de Domain Controllers"   $domainControllers.Count "Green"
    Write-Check "Quantidade de grupos"               $GroupsCount            "Green"
    Write-Check "Quantidade de OUs"                  $OUsCount               "Green"

    Write-Section "INFORMAÇÕES DE OBJETOS" "Cyan"
    Write-Check "Usuários com senha que nunca expira"  $userspne.Count
    Write-Check "Usuários desabilitados"               $usersdisabled.Count
    Write-Check "Usuários sem logon (180 dias)"        $users180dias.Count
    Write-Check "Usuários no grupo Domain Admins"      $usersadmin.Count
    Write-Check "Usuários no grupo Administrators"     $usersadmin1.Count
    Write-Check "Usuários inativos (180 dias)"         $inativos.Count
    Write-Check "Usuários com SIDHistory"              $userssidhistory.Count
    Write-Check "AdminSDHolder"                        $AdminsdHolder.Count
    Write-Check "Conta Guest habilitada"               $($Guest.Enabled)

    Write-Section "POLÍTICA DE SENHA DO DOMÍNIO" "Cyan"
    Write-Check "Complexidade habilitada"              $passPolicy.ComplexityEnabled       "Green"
    Write-Check "Tamanho mínimo da senha"              $passPolicy.MinPasswordLength       "Green"
    Write-Check "Histórico de senhas"                  $passPolicy.PasswordHistoryCount    "Green"
    Write-Check "Tentativas antes do bloqueio"         $passPolicy.LockoutThreshold        "Green"
    Write-Check "Duração do bloqueio"                  $passPolicy.LockoutDuration         "Green"
    Write-Check "Idade máxima da senha (dias)"         $passPolicy.MaxPasswordAge.Days     "Green"
    Write-Check "Idade mínima da senha (dias)"         $passPolicy.MinPasswordAge.Days     "Green"

    Write-Section "GOLDEN TICKET ATTACK" "Red"
    Write-Check "krbtgt modificada em"                $krbtgt.WhenChanged.ToString()      "Yellow"

    Write-Section "DCSYNC ATTACK" "Red"
    Write-Check "Criptografia reversível habilitada"  $reversiblePwd                      $(if($reversiblePwd){"Red"}else{"Green"})

    Write-Section "PRINT SPOOLER / KERBEROS DELEGATION" "Red"
    Write-Check "Objetos com Kerberos Delegation"     $kerbdelegation.Count
    Write-Check "DCs com Print Spooler habilitado"    $spoolerEnabled.Count
    if ($spoolerEnabled.Count -gt 0) {
        $spoolerEnabled | ForEach-Object { Write-Host "      → $_" -ForegroundColor Red }
    }

    # --- Exportação CSV ---
    Write-Section "EXPORTANDO ARQUIVOS CSV" "DarkGray"
    $userspne      | Export-Csv "$($CONFIG.OutputFolder)\ad-users-password-never-expire.csv" -NoTypeInformation -Encoding UTF8
    $usersadmin    | Export-Csv "$($CONFIG.OutputFolder)\ad-users-domain-admins.csv"         -NoTypeInformation -Encoding UTF8
    $usersadmin1   | Export-Csv "$($CONFIG.OutputFolder)\ad-users-administrators.csv"        -NoTypeInformation -Encoding UTF8
    $usersdisabled | Export-Csv "$($CONFIG.OutputFolder)\ad-users-disabled.csv"              -NoTypeInformation -Encoding UTF8
    $users180dias  | Export-Csv "$($CONFIG.OutputFolder)\ad-users-no-logon-180d.csv"         -NoTypeInformation -Encoding UTF8
    $userssidhistory | Export-Csv "$($CONFIG.OutputFolder)\ad-users-sidhistory.csv"          -NoTypeInformation -Encoding UTF8
    $AdminsdHolder | Export-Csv "$($CONFIG.OutputFolder)\ad-adminSDHolder.csv"               -NoTypeInformation -Encoding UTF8
    $kerbdelegation| Export-Csv "$($CONFIG.OutputFolder)\ad-kerberos-delegation.csv"         -NoTypeInformation -Encoding UTF8
    $inativos      | Export-Csv "$($CONFIG.OutputFolder)\ad-users-inactive.csv"              -NoTypeInformation -Encoding UTF8
    if ($spoolerEnabled) {
        $spoolerEnabled | ForEach-Object { [PSCustomObject]@{DC=$_} } |
            Export-Csv "$($CONFIG.OutputFolder)\ad-printspooler-enabled.csv" -NoTypeInformation -Encoding UTF8
    }

    # Relatório TXT
    $relatorio = @"
AD SECURITY ASSESSMENT - $(Get-Date)
=====================================================
Domínio              : $DomainName
Nível funcional      : $ForestFunctionalLevel
Usuários             : $UsersCount
Computadores         : $ComputersCount
Domain Controllers   : $($domainControllers.Count)
Grupos               : $GroupsCount
OUs                  : $OUsCount
-----------------------------------------------------
Senha nunca expira   : $($userspne.Count)
Usuários desabilitados: $($usersdisabled.Count)
Sem logon 180d       : $($users180dias.Count)
Domain Admins        : $($usersadmin.Count)
Administrators       : $($usersadmin1.Count)
Inativos 180d        : $($inativos.Count)
SIDHistory           : $($userssidhistory.Count)
AdminSDHolder        : $($AdminsdHolder.Count)
Guest habilitado     : $($Guest.Enabled)
-----------------------------------------------------
POLITICA DE SENHA
Complexidade         : $($passPolicy.ComplexityEnabled)
Tamanho mínimo       : $($passPolicy.MinPasswordLength)
Histórico            : $($passPolicy.PasswordHistoryCount)
Bloqueio após        : $($passPolicy.LockoutThreshold) tentativas
Duração bloqueio     : $($passPolicy.LockoutDuration)
Idade máxima         : $($passPolicy.MaxPasswordAge.Days) dias
Idade mínima         : $($passPolicy.MinPasswordAge.Days) dias
-----------------------------------------------------
GOLDEN TICKET: krbtgt modificada em $($krbtgt.WhenChanged)
DCSYNC: Criptografia reversível = $reversiblePwd
PRINT SPOOLER / Kerberos Delegation: $($kerbdelegation.Count) objetos
DCs com Print Spooler ativo: $($spoolerEnabled -join ', ')
=====================================================
"@
    $relatorio | Set-Content "$($CONFIG.OutputFolder)\ADSecAssessment-Overview.txt" -Encoding UTF8
    Write-Host "  [✓] Relatório TXT salvo" -ForegroundColor Green

    $csvCount = (Get-ChildItem "$($CONFIG.OutputFolder)\ad-*.csv" -ErrorAction SilentlyContinue).Count
    Write-Host "  [✓] $csvCount arquivos CSV exportados para $($CONFIG.OutputFolder)" -ForegroundColor Green
}

# ============================================================
# MÓDULO 2 — RANSOMWARE READINESS ASSESSMENT
# ============================================================
function Invoke-RansomwareAssessment {

    Write-Section "MÓDULO 2 — RANSOMWARE READINESS ASSESSMENT" "Magenta"

    $domainControllers = Get-ADDomainController -Filter *
    $riskScore = 0
    $riskItems = @()

    # --- CHECK 1: SMBv1 ---
    Write-Host "`n  [CHECK 1/8] SMBv1 nos Domain Controllers" -ForegroundColor Cyan
    $smbv1Results = @()
    foreach ($dc in $domainControllers) {
        try {
            $smb1 = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                (Get-SmbServerConfiguration).EnableSMB1Protocol
            } -ErrorAction Stop
            $smbv1Results += [PSCustomObject]@{ DC=$dc.HostName; SMBv1=$smb1; Risco=if($smb1){"CRITICO"}else{"OK"} }
            if ($smb1) { Write-Host "    [!] $($dc.HostName) — SMBv1 HABILITADO" -ForegroundColor Red }
            else       { Write-Host "    [OK] $($dc.HostName) — SMBv1 desabilitado" -ForegroundColor Green }
        } catch { Write-Host "    [?] $($dc.HostName) — não foi possível verificar" -ForegroundColor Yellow }
    }
    if (($smbv1Results | Where-Object {$_.SMBv1}).Count -gt 0) { $riskScore += 25; $riskItems += "[CRITICO +25] SMBv1 habilitado em DCs" }
    $smbv1Results | Export-Csv "$($CONFIG.OutputFolder)\ransom-smbv1.csv" -NoTypeInformation -Encoding UTF8

    # --- CHECK 2: AS-REP Roasting ---
    Write-Host "`n  [CHECK 2/8] AS-REP Roasting — Contas sem pré-autenticação Kerberos" -ForegroundColor Cyan
    $asrepUsers = Get-ADUser -Filter * -Properties DoesNotRequirePreAuth,Enabled |
        Where-Object { $_.DoesNotRequirePreAuth -eq $true -and $_.Enabled -eq $true }
    if ($asrepUsers.Count -gt 0) {
        Write-Host "    [!] $($asrepUsers.Count) conta(s) vulnerável(is) ao AS-REP Roasting:" -ForegroundColor Red
        $asrepUsers | ForEach-Object { Write-Host "        → $($_.SamAccountName)" -ForegroundColor Red }
        $riskScore += 15; $riskItems += "[ALTO   +15] Contas vulneráveis a AS-REP Roasting ($($asrepUsers.Count))"
    } else { Write-Host "    [OK] Nenhuma conta vulnerável ao AS-REP Roasting" -ForegroundColor Green }
    $asrepUsers | Select-Object Name,SamAccountName,Enabled,DoesNotRequirePreAuth |
        Export-Csv "$($CONFIG.OutputFolder)\ransom-asrep-roasting.csv" -NoTypeInformation -Encoding UTF8

    # --- CHECK 3: Kerberoasting ---
    Write-Host "`n  [CHECK 3/8] Kerberoasting — Contas de usuário com SPNs" -ForegroundColor Cyan
    $kerbUsers = Get-ADUser -Filter {ServicePrincipalName -like "*"} `
        -Properties SamAccountName,ServicePrincipalName,PasswordLastSet,Enabled |
        Where-Object { $_.Enabled -eq $true }
    if ($kerbUsers.Count -gt 0) {
        Write-Host "    [!] $($kerbUsers.Count) conta(s) kerberoastável(is):" -ForegroundColor Red
        $kerbUsers | ForEach-Object {
            $days = ((Get-Date) - $_.PasswordLastSet).Days
            Write-Host "        → $($_.SamAccountName) | Senha com $days dias $( if($days -gt 365){'— SENHA ANTIGA!'} )" -ForegroundColor Red
        }
        $riskScore += 15; $riskItems += "[ALTO   +15] Contas kerberoastáveis encontradas ($($kerbUsers.Count))"
    } else { Write-Host "    [OK] Nenhuma conta de usuário com SPN" -ForegroundColor Green }
    $kerbUsers | Select-Object Name,SamAccountName,ServicePrincipalName,PasswordLastSet |
        Export-Csv "$($CONFIG.OutputFolder)\ransom-kerberoasting.csv" -NoTypeInformation -Encoding UTF8

    # --- CHECK 4: LAPS ---
    Write-Host "`n  [CHECK 4/8] LAPS — Local Administrator Password Solution" -ForegroundColor Cyan
    $lapsv1 = Get-ADObject -SearchBase "CN=Schema,CN=Configuration,$((Get-ADDomain).DistinguishedName)" `
        -LDAPFilter "(lDAPDisplayName=ms-Mcs-AdmPwd)" -SearchScope Subtree -ErrorAction SilentlyContinue
    $lapsv2 = Get-ADObject -SearchBase "CN=Schema,CN=Configuration,$((Get-ADDomain).DistinguishedName)" `
        -LDAPFilter "(lDAPDisplayName=msLAPS-Password)" -SearchScope Subtree -ErrorAction SilentlyContinue
    if ($lapsv1 -or $lapsv2) {
        Write-Host "    [OK] LAPS instalado no schema do AD" -ForegroundColor Green
        $semLaps = Get-ADComputer -Filter * -Properties "ms-Mcs-AdmPwdExpirationTime","msLAPS-PasswordExpirationTime" |
            Where-Object { -not $_."ms-Mcs-AdmPwdExpirationTime" -and -not $_."msLAPS-PasswordExpirationTime" }
        if ($semLaps.Count -gt 0) {
            Write-Host "    [!] $($semLaps.Count) computador(es) SEM LAPS configurado" -ForegroundColor Red
            $semLaps | Select-Object Name,DNSHostName | Export-Csv "$($CONFIG.OutputFolder)\ransom-sem-laps.csv" -NoTypeInformation -Encoding UTF8
        } else { Write-Host "    [OK] Todos os computadores com LAPS configurado" -ForegroundColor Green }
    } else {
        Write-Host "    [!] LAPS NÃO está instalado no ambiente!" -ForegroundColor Red
        $riskScore += 20; $riskItems += "[CRITICO +20] LAPS não instalado no ambiente"
    }

    # --- CHECK 5: Grupos sensíveis ---
    Write-Host "`n  [CHECK 5/8] Grupos Sensíveis (Backup/Account/Server/Print Operators)" -ForegroundColor Cyan
    $sensitiveGroups = @("Backup Operators","Account Operators","Server Operators","Print Operators")
    $groupResults = @()
    foreach ($g in $sensitiveGroups) {
        try {
            $members = Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop |
                Get-ADUser -Properties Enabled -ErrorAction SilentlyContinue |
                Where-Object { $_.Enabled -eq $true }
            $count = ($members | Measure-Object).Count
            if ($count -gt 0) {
                Write-Host "    [!] '$g' — $count membro(s) ativo(s)" -ForegroundColor Red
                $members | ForEach-Object { Write-Host "        → $($_.SamAccountName)" -ForegroundColor Red }
            } else { Write-Host "    [OK] '$g' — sem membros ativos" -ForegroundColor Green }
            $groupResults += [PSCustomObject]@{ Grupo=$g; Membros=$count; Risco=if($count -gt 0){"ALTO"}else{"OK"} }
        } catch { Write-Host "    [INFO] '$g' não encontrado" -ForegroundColor DarkGray }
    }
    $groupResults | Export-Csv "$($CONFIG.OutputFolder)\ransom-grupos-sensiveis.csv" -NoTypeInformation -Encoding UTF8

    # --- CHECK 6: WDigest ---
    Write-Host "`n  [CHECK 6/8] WDigest Authentication nos Domain Controllers" -ForegroundColor Cyan
    $wdigestResults = @()
    foreach ($dc in $domainControllers) {
        try {
            $val = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                $p = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
                if (Test-Path $p) { (Get-ItemProperty $p -Name UseLogonCredential -EA SilentlyContinue).UseLogonCredential }
                else { 0 }
            } -ErrorAction Stop
            $enabled = ($val -eq 1)
            $wdigestResults += [PSCustomObject]@{ DC=$dc.HostName; WDigest=$enabled; Risco=if($enabled){"CRITICO"}else{"OK"} }
            if ($enabled) { Write-Host "    [!] $($dc.HostName) — WDigest HABILITADO (plaintext na memória!)" -ForegroundColor Red }
            else          { Write-Host "    [OK] $($dc.HostName) — WDigest desabilitado" -ForegroundColor Green }
        } catch { Write-Host "    [?] $($dc.HostName) — não foi possível verificar" -ForegroundColor Yellow }
    }
    if (($wdigestResults | Where-Object {$_.WDigest}).Count -gt 0) {
        $riskScore += 20; $riskItems += "[CRITICO +20] WDigest habilitado — credenciais em plaintext"
    }
    $wdigestResults | Export-Csv "$($CONFIG.OutputFolder)\ransom-wdigest.csv" -NoTypeInformation -Encoding UTF8

    # --- CHECK 7: AD Recycle Bin ---
    Write-Host "`n  [CHECK 7/8] AD Recycle Bin" -ForegroundColor Cyan
    $rb = Get-ADOptionalFeature -Filter {Name -like "Recycle Bin Feature"}
    if ($rb.EnabledScopes.Count -gt 0) {
        Write-Host "    [OK] AD Recycle Bin habilitado" -ForegroundColor Green
    } else {
        Write-Host "    [!] AD Recycle Bin DESABILITADO — recuperação pós-ataque comprometida" -ForegroundColor Red
        $riskScore += 5; $riskItems += "[MEDIO  +5 ] AD Recycle Bin desabilitado"
    }

    # --- CHECK 8: Protected Users ---
    Write-Host "`n  [CHECK 8/8] Protected Users Security Group" -ForegroundColor Cyan
    $domAdmins      = Get-ADGroupMember -Identity "Domain Admins" -Recursive | Get-ADUser -Properties Enabled | Where-Object {$_.Enabled}
    $protectedUsers = Get-ADGroupMember -Identity "Protected Users" -ErrorAction SilentlyContinue
    $notProtected   = $domAdmins | Where-Object { $u = $_; -not ($protectedUsers | Where-Object {$_.SamAccountName -eq $u.SamAccountName}) }
    if ($notProtected.Count -gt 0) {
        Write-Host "    [!] $($notProtected.Count) Domain Admin(s) fora do grupo 'Protected Users':" -ForegroundColor Red
        $notProtected | ForEach-Object { Write-Host "        → $($_.SamAccountName)" -ForegroundColor Red }
        $riskScore += 10; $riskItems += "[ALTO   +10] Domain Admins sem Protected Users ($($notProtected.Count))"
    } else { Write-Host "    [OK] Todos os Domain Admins no grupo Protected Users" -ForegroundColor Green }
    $notProtected | Select-Object Name,SamAccountName,Enabled |
        Export-Csv "$($CONFIG.OutputFolder)\ransom-admins-sem-protecao.csv" -NoTypeInformation -Encoding UTF8

    # --- SCORE FINAL ---
    $riskLevel = switch ($true) {
        {$riskScore -ge 60} {"CRÍTICO"; break}
        {$riskScore -ge 40} {"ALTO";    break}
        {$riskScore -ge 20} {"MÉDIO";   break}
        default             {"BAIXO"}
    }
    $riskColor = if ($riskScore -ge 40) {"Red"} elseif ($riskScore -ge 20) {"Yellow"} else {"Green"}

    Write-Section "RANSOMWARE RISK SCORE" "Magenta"
    Write-Host "  Score: $riskScore / 100  —  Nível: $riskLevel" -ForegroundColor $riskColor
    Write-Host ""
    $riskItems | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }

    [PSCustomObject]@{
        Data       = (Get-Date)
        Dominio    = (Get-ADDomain).DNSRoot
        Score      = $riskScore
        Nivel      = $riskLevel
        Findings   = ($riskItems -join " | ")
    } | Export-Csv "$($CONFIG.OutputFolder)\ransom-risk-score.csv" -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-Host "  [+] Arquivos CSV do módulo Ransomware exportados para $($CONFIG.OutputFolder)" -ForegroundColor Green
}

# ============================================================
# MÓDULO 3/4/5 — AUDITORIA DE QUALIDADE DE SENHAS (DSInternals)
# ============================================================
function Invoke-PasswordAudit {
    param([string]$Tipo)

    $moduleTitle = switch ($Tipo) {
        "Padrao"     { "MÓDULO 3 — PASSWORD AUDIT (Padrão)" }
        "Dicionario" { "MÓDULO 4 — PASSWORD AUDIT (Dicionário)" }
        "HIBP"       { "MÓDULO 5 — PASSWORD AUDIT (HIBP)" }
    }
    Write-Section $moduleTitle "Cyan"

    if (-not (Get-Module -ListAvailable -Name DSInternals)) {
        Write-Host "  [!] Módulo DSInternals não encontrado." -ForegroundColor Red
        Write-Host "      Execute: Install-Module DSInternals -Force" -ForegroundColor Yellow
        return
    }
    Import-Module DSInternals -ErrorAction SilentlyContinue

    if (-not (Test-Connection -ComputerName $CONFIG.Servidor -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
        Write-Host "  [!] Servidor '$($CONFIG.Servidor)' inacessível." -ForegroundColor Red
        Write-Host "      Verifique a variável `$CONFIG.Servidor no topo do script." -ForegroundColor Yellow
        return
    }

    Write-Host "  [*] Coletando hashes do AD ($($CONFIG.Servidor))..." -ForegroundColor DarkGray
    try {
        $accounts = Get-ADReplAccount -All -Server $CONFIG.Servidor -NamingContext $CONFIG.Dominio

        switch ($Tipo) {
            "Padrao" {
                $accounts | Test-PasswordQuality
            }
            "Dicionario" {
                if (-not (Test-Path $CONFIG.Wordlist)) {
                    Write-Host "  [!] Wordlist não encontrada: $($CONFIG.Wordlist)" -ForegroundColor Red; return
                }
                Write-Host "  [*] Usando dicionário: $($CONFIG.Wordlist)" -ForegroundColor DarkGray
                $accounts | Test-PasswordQuality -WeakPasswordsFile $CONFIG.Wordlist
            }
            "HIBP" {
                if (-not (Test-Path $CONFIG.HIBPFile)) {
                    Write-Host "  [!] Arquivo HIBP não encontrado: $($CONFIG.HIBPFile)" -ForegroundColor Red
                    Write-Host "      Baixe com: haveibeenpwned-downloader -n pwnedpasswords_ntlm" -ForegroundColor Yellow
                    return
                }
                Write-Host "  [*] Usando base HIBP: $($CONFIG.HIBPFile)" -ForegroundColor DarkGray
                $accounts | Test-PasswordQuality -WeakPasswordHashesFile $CONFIG.HIBPFile
            }
        }
        Write-Host "  [✓] Auditoria de senhas concluída." -ForegroundColor Green
    } catch {
        Write-Host "  [!] Erro: $_" -ForegroundColor Red
    }
}

# ============================================================
# MÓDULO 6 — HASH GENERATOR SHA1
# ============================================================
function Invoke-SHA1Generator {
    Write-Section "MÓDULO 6 — HASH GENERATOR SHA1" "Cyan"

    if (-not (Test-Path $CONFIG.Wordlist)) {
        Write-Host "  [!] Wordlist não encontrada: $($CONFIG.Wordlist)" -ForegroundColor Red
        Write-Host "      Defina o caminho correto em `$CONFIG.Wordlist" -ForegroundColor Yellow
        return
    }

    Write-Host "  [*] Entrada : $($CONFIG.Wordlist)" -ForegroundColor DarkGray
    Write-Host "  [*] Saída   : $($CONFIG.SHA1Output)" -ForegroundColor DarkGray

    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    Get-Content $CONFIG.Wordlist | ForEach-Object {
        $bytes  = [System.Text.Encoding]::UTF8.GetBytes($_)
        $hash   = ($sha1.ComputeHash($bytes) | ForEach-Object { "{0:X2}" -f $_ }) -join ""
        $hash
    } | Set-Content $CONFIG.SHA1Output -Encoding UTF8

    $count = (Get-Content $CONFIG.SHA1Output).Count
    Write-Host "  [✓] $count hashes SHA1 gerados em: $($CONFIG.SHA1Output)" -ForegroundColor Green
}

# ============================================================
# MÓDULO 7 — HASH GENERATOR NTLM
# ============================================================
function Invoke-NTLMGenerator {
    Write-Section "MÓDULO 7 — HASH GENERATOR NTLM" "Cyan"

    if (-not (Get-Module -ListAvailable -Name DSInternals)) {
        Write-Host "  [!] Módulo DSInternals não encontrado." -ForegroundColor Red
        Write-Host "      Execute: Install-Module DSInternals -Force" -ForegroundColor Yellow
        return
    }
    Import-Module DSInternals -ErrorAction SilentlyContinue

    if (-not (Test-Path $CONFIG.Wordlist)) {
        Write-Host "  [!] Wordlist não encontrada: $($CONFIG.Wordlist)" -ForegroundColor Red
        Write-Host "      Defina o caminho correto em `$CONFIG.Wordlist" -ForegroundColor Yellow
        return
    }

    Write-Host "  [*] Entrada : $($CONFIG.Wordlist)" -ForegroundColor DarkGray
    Write-Host "  [*] Saída   : $($CONFIG.NTLMOutput)" -ForegroundColor DarkGray

    Get-Content $CONFIG.Wordlist | ForEach-Object {
        $secure = ConvertTo-SecureString -String $_ -AsPlainText -Force
        ConvertTo-NTHash -Password $secure
    } | Set-Content $CONFIG.NTLMOutput -Encoding UTF8

    $count = (Get-Content $CONFIG.NTLMOutput).Count
    Write-Host "  [✓] $count hashes NTLM gerados em: $($CONFIG.NTLMOutput)" -ForegroundColor Green
}

# ============================================================
# EXECUÇÃO PRINCIPAL
# ============================================================

Show-Banner
Ensure-OutputFolder

do {
    Show-Banner
    Show-MainMenu

    $opcao = Read-Host "  Selecione uma opção"

    switch ($opcao.ToUpper()) {
        "1" {
            Invoke-ADSecurityAssessment
            Generate-FileHashes
            Write-Host "`n  Pressione ENTER para voltar ao menu..." -ForegroundColor DarkGray
            Read-Host | Out-Null
        }
        "2" {
            Invoke-RansomwareAssessment
            Generate-FileHashes
            Write-Host "`n  Pressione ENTER para voltar ao menu..." -ForegroundColor DarkGray
            Read-Host | Out-Null
        }
        "3" {
            Invoke-PasswordAudit -Tipo "Padrao"
            Write-Host "`n  Pressione ENTER para voltar ao menu..." -ForegroundColor DarkGray
            Read-Host | Out-Null
        }
        "4" {
            Invoke-PasswordAudit -Tipo "Dicionario"
            Write-Host "`n  Pressione ENTER para voltar ao menu..." -ForegroundColor DarkGray
            Read-Host | Out-Null
        }
        "5" {
            Invoke-PasswordAudit -Tipo "HIBP"
            Write-Host "`n  Pressione ENTER para voltar ao menu..." -ForegroundColor DarkGray
            Read-Host | Out-Null
        }
        "6" {
            Invoke-SHA1Generator
            Write-Host "`n  Pressione ENTER para voltar ao menu..." -ForegroundColor DarkGray
            Read-Host | Out-Null
        }
        "7" {
            Invoke-NTLMGenerator
            Write-Host "`n  Pressione ENTER para voltar ao menu..." -ForegroundColor DarkGray
            Read-Host | Out-Null
        }
        "8" {
            Invoke-ADSecurityAssessment
            Invoke-RansomwareAssessment
            Generate-FileHashes
            Write-Host "`n  [✓] Full Assessment concluído. Todos os arquivos em $($CONFIG.OutputFolder)" -ForegroundColor Green
            Write-Host "`n  Pressione ENTER para voltar ao menu..." -ForegroundColor DarkGray
            Read-Host | Out-Null
        }
        "Q" {
            Write-Host ""
            Write-Host "  Saindo do AD Security Suite. Até logo!" -ForegroundColor DarkCyan
            Write-Host "  danieldonda.com | Hackers Hive" -ForegroundColor DarkGray
            Write-Host ""
            exit 0
        }
        Default {
            Write-Host "  [!] Opção inválida. Tente novamente." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }

} while ($true)
