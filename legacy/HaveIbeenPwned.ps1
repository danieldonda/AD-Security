#Requires -Modules DSInternals
<#
.SYNOPSIS
    Auditoria de qualidade de senhas no Active Directory - Hackers Hive
.DESCRIPTION
    Verifica a qualidade das senhas do AD usando DSInternals.
    Suporta verificação por dicionário e integração com HaveIBeenPwned (HIBP).
.NOTES
    Autor  : Hackers Hive | danieldonda.com
    Versão : 2.0
    Requer : DSInternals Module (Install-Module DSInternals -Force)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────
#  CONFIGURAÇÕES
# ─────────────────────────────────────────────
$CONFIG = @{
    Servidor       = "WS2K16ADDS"
    Dominio        = "dc=ITSEC,dc=LAB"
    Dicionario     = "C:\scripts\senhas-texto-purex.txt"
    HaveIBeenPwned = "C:\pwned-passwords-ntlm-ordered-by-hash-v8.txt"
    HIBPDownloader = "https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader"
}

# ─────────────────────────────────────────────
#  FUNÇÕES AUXILIARES
# ─────────────────────────────────────────────
function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗ ███████╗    ██╗  ██╗██╗██╗   ██╗███████╗" -ForegroundColor Cyan
    Write-Host "  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗██╔════╝    ██║  ██║██║██║   ██║██╔════╝" -ForegroundColor Cyan
    Write-Host "  ███████║███████║██║     █████╔╝ █████╗  ██████╔╝███████╗    ███████║██║██║   ██║█████╗  " -ForegroundColor Cyan
    Write-Host "  ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗╚════██║    ██╔══██║██║╚██╗ ██╔╝██╔══╝  " -ForegroundColor Cyan
    Write-Host "  ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║███████║    ██║  ██║██║ ╚████╔╝ ███████╗" -ForegroundColor Cyan
    Write-Host "  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  AD Password Quality Audit | hackershive.io" -ForegroundColor DarkCyan
    Write-Host ""
}

function Test-Prerequisites {
    # Verifica módulo DSInternals
    if (-not (Get-Module -ListAvailable -Name DSInternals)) {
        Write-Host "  [!] Módulo DSInternals não encontrado." -ForegroundColor Red
        Write-Host "      Execute: Install-Module DSInternals -Force" -ForegroundColor Yellow
        exit 1
    }

    # Verifica conectividade com o servidor AD
    if (-not (Test-Connection -ComputerName $CONFIG.Servidor -Count 1 -Quiet)) {
        Write-Host "  [!] Servidor '$($CONFIG.Servidor)' inacessível." -ForegroundColor Red
        exit 1
    }
}

function Show-FileStatus {
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Status dos arquivos de suporte:" -ForegroundColor White
    
    # Dicionário
    if (Test-Path -Path $CONFIG.Dicionario -PathType Leaf) {
        $tamanho = [math]::Round((Get-Item $CONFIG.Dicionario).Length / 1MB, 2)
        Write-Host "  [✓] Dicionário encontrado ($tamanho MB)" -ForegroundColor Green
    } else {
        Write-Host "  [✗] Dicionário não encontrado: $($CONFIG.Dicionario)" -ForegroundColor Red
    }

    # HIBP
    if (Test-Path -Path $CONFIG.HaveIBeenPwned -PathType Leaf) {
        $tamanhoGB = [math]::Round((Get-Item $CONFIG.HaveIBeenPwned).Length / 1GB, 2)
        Write-Host "  [✓] HIBP NTLM encontrado ($tamanhoGB GB)" -ForegroundColor Green
    } else {
        Write-Host "  [✗] HIBP não encontrado: $($CONFIG.HaveIBeenPwned)" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Como baixar o arquivo HIBP NTLM:" -ForegroundColor Yellow
        Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor DarkYellow
        Write-Host "  │ Opção 1 - Downloader oficial (.NET obrigatório):        │" -ForegroundColor DarkYellow
        Write-Host "  │  dotnet tool install -g haveibeenpwned-downloader       │" -ForegroundColor White
        Write-Host "  │  haveibeenpwned-downloader -n pwnedpasswords_ntlm      │" -ForegroundColor White
        Write-Host "  │                                                          │" -ForegroundColor DarkYellow
        Write-Host "  │ Opção 2 - Download direto (Cloudflare CDN ~30 GB):     │" -ForegroundColor DarkYellow
        Write-Host "  │  $($CONFIG.HIBPDownloader)  │" -ForegroundColor White
        Write-Host "  │                                                          │" -ForegroundColor DarkYellow
        Write-Host "  │  ⚠ Arquivo NTLM v8 ordenado por hash (~30 GB)          │" -ForegroundColor DarkYellow
        Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor DarkYellow
    }
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor DarkGray
}

function Show-Menu {
    Write-Host ""
    Write-Host "  Selecione uma opção:" -ForegroundColor White
    Write-Host ""
    Write-Host "  [1] Auditoria padrão de senhas no AD" -ForegroundColor Cyan
    Write-Host "  [2] Auditoria com dicionário de senhas fracas" -ForegroundColor Cyan
    Write-Host "  [3] Auditoria com HaveIBeenPwned (HIBP NTLM)" -ForegroundColor Cyan
    Write-Host "  [Q] Sair" -ForegroundColor DarkGray
    Write-Host ""
}

function Invoke-Audit {
    param(
        [Parameter(Mandatory)][string]$Tipo
    )

    Write-Host ""
    Write-Host "  [*] Iniciando auditoria: $Tipo" -ForegroundColor Yellow
    Write-Host "  [*] Servidor : $($CONFIG.Servidor)" -ForegroundColor DarkGray
    Write-Host "  [*] Domínio  : $($CONFIG.Dominio)" -ForegroundColor DarkGray
    Write-Host ""

    try {
        $accounts = Get-ADReplAccount -All -Server $CONFIG.Servidor -NamingContext $CONFIG.Dominio

        switch ($Tipo) {
            "Padrao"      { $accounts | Test-PasswordQuality }
            "Dicionario"  {
                if (-not (Test-Path $CONFIG.Dicionario)) {
                    throw "Arquivo de dicionário não encontrado: $($CONFIG.Dicionario)"
                }
                $accounts | Test-PasswordQuality -WeakPasswordsFile $CONFIG.Dicionario
            }
            "HIBP"        {
                if (-not (Test-Path $CONFIG.HaveIBeenPwned)) {
                    throw "Arquivo HIBP não encontrado: $($CONFIG.HaveIBeenPwned)"
                }
                $accounts | Test-PasswordQuality -WeakPasswordHashesFile $CONFIG.HaveIBeenPwned
            }
        }

        Write-Host ""
        Write-Host "  [✓] Auditoria concluída com sucesso." -ForegroundColor Green

    } catch {
        Write-Host "  [!] Erro durante a auditoria: $_" -ForegroundColor Red
    }
}

# ─────────────────────────────────────────────
#  EXECUÇÃO PRINCIPAL
# ─────────────────────────────────────────────
Write-Banner
Test-Prerequisites
Show-FileStatus
Show-Menu

do {
    $opcao = Read-Host "  Opção"

    switch ($opcao.ToUpper()) {
        "1" { Invoke-Audit -Tipo "Padrao"     ; break }
        "2" { Invoke-Audit -Tipo "Dicionario" ; break }
        "3" { Invoke-Audit -Tipo "HIBP"       ; break }
        "Q" { Write-Host "  Saindo..." -ForegroundColor DarkGray; exit 0 }
        Default { Write-Host "  [!] Opção inválida. Tente novamente." -ForegroundColor Red }
    }

} while ($opcao.ToUpper() -eq "Q" -or $opcao -notin @("1","2","3","Q"))
