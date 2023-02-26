clear
# Instala o Directory Services Internals PowerShell Module and Framework
# Install-Module DSInternals -Force

# Declarações de variaveis 

$servidor = "WS2K16ADDS"
$dominio = "dc=ITSEC,dc=LAB"
$dicionario = "C:\scripts\senhas-texto-purex.txt"
$HaveIBeenPwned = "c:\pwned-passwords-ntlm-ordered-by-hash-v8.txt"

# Validação de arquivos.
if (-not (Test-Path -Path $dicionario -PathType Leaf)) {
    Write-Host "Arquivo de dicionário não encontrado. Defina um arquivo de dicionário no script." -ForegroundColor Yellow
}
if (-not (Test-Path -Path $HaveIBeenPwned -PathType Leaf)) {
    Write-Host "Arquivo HaveIBeenPwned não encontrado, acesse https://haveibeenpwned.com/Passwords e baixe o arquivo de senhas no formato NTLM ordenado por hash." -ForegroundColor Yellow
}

# Exibe as opções do menu
Write-Host "---------------------------------------------------------------------------"
Write-Host "Selecione uma das opções abaixo:"
Write-Host "---------------------------------------------------------------------------"
Write-Host "1 - Testar a qualidade das senhas no Active Directory"
Write-Host "2 - Testar a qualidade das senhas no Active Directory usando dicionários"
Write-Host "3 - Testar a qualidade das senhas no Active Directory usando HaveIBeenPwned"

# Lê a opção escolhida pelo usuário
$opcao = Read-Host "Digite o número da opção escolhida"

# Executa o código associado à opção escolhida
Switch ($opcao) {
    1 { # Testar a qualidade das senhas no Active Directory
      Get-ADReplAccount -All -Server $servidor -NamingContext $dominio | Test-PasswordQuality
    }
    2 { # Testar a qualidade das senhas no Active Directory usando dicionários
      Get-ADReplAccount -All -Server $servidor -NamingContext $dominio | Test-PasswordQuality -WeakPasswordsFile $dicionario
    }
    3 { # Testar a qualidade das senhas no Active Directory usando HaveIBeenPwned
     echo   Get-ADReplAccount -All -Server $servidor -NamingContext $dominio | Test-PasswordQuality -WeakPasswordHashesFile $HaveIBeenPwned
    }
    Default {
        Write-Host "Opção inválida!"
    }
}


