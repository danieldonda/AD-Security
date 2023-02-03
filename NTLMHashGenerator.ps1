# Este script permite calcular o hash NTLM a partir de uma lista de senhas em um arquivo de texto puro.
# Depende do modulo DSInternals -  https://github.com/MichaelGrafnetter/DSInternals 
# Ideal para criar um dicionario de senhas
clear

if (!(Get-Module -Name "DSInternals")) {
  Write-Host "Modulo do DSInternals não encontrado. Instalando..."
  Install-Module -Name DSInternals -force
}

Write-Host "═════════════════════════════════════════"
Write-Host "╔╗╔╔╦╗╦  ╔╦╗  ╔═╗╔═╗╔╗╔╔═╗╦═╗╔═╗╔╦╗╔═╗╦═╗"
Write-Host "║║║ ║ ║  ║║║  ║ ╦║╣ ║║║║╣ ╠╦╝╠═╣ ║ ║ ║╠╦╝"
Write-Host "╝╚╝ ╩ ╩═╝╩ ╩  ╚═╝╚═╝╝╚╝╚═╝╩╚═╩ ╩ ╩ ╚═╝╩╚═"
Write-Host "═════════════════════════════════════════"

# Define o caminho do arquivo de entrada
$inputFile = "C:\scripts\senhas-texto-puro.txt"
# Define o caminho do arquivo de saída
$outputFile = "C:\scripts\senhas-NTLMhash.txt"

if (Test-Path $inputFile) {
 

 Get-Content $inputFile | ForEach-Object {
    # Armazena o conteúdo da linha como uma string segura
    $pwd = ConvertTo-SecureString -String $_ -AsPlainText -Force

    # Converte a string segura para hash NTLM
    ConvertTo-NTHash -Password $pwd

} | Set-Content $outputFile

 Write-Host "Arquivo criado com sucesso: $outputFile"

} else {
  Write-Host "O arquivo não existe: $inputFile"
}