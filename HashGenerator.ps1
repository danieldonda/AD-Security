# Este script usa o .NET Framework para calcular o hash SHA-1 de um arquivo de texto puro. 
# Ideal para criar um dicionario de senhas

Write-Host "═════════════════════════════════════════"
Write-Host "╦ ╦╔═╗╔═╗╦ ╦  ╔═╗╔═╗╔╗╔╔═╗╦═╗╔═╗╔╦╗╔═╗╦═╗"
Write-Host "╠═╣╠═╣╚═╗╠═╣  ║ ╦║╣ ║║║║╣ ╠╦╝╠═╣ ║ ║ ║╠╦╝"
Write-Host "╩ ╩╩ ╩╚═╝╩ ╩  ╚═╝╚═╝╝╚╝╚═╝╩╚═╩ ╩ ╩ ╚═╝╩╚═"
Write-Host "═════════════════════════════════════════"


# Define o caminho do arquivo de entrada
$inputFile = "C:\scripts\senhas-texto-puro.txt"
# Define o caminho do arquivo de saída
$outputFile = "C:\scripts\senhas-hash1.txt"

if (Test-Path $inputFile) {
 
# Cria uma instância do algoritmo de hash SHA1.
$hash = [System.Security.Cryptography.SHA1]::Create()

Get-Content $inputFile | ForEach-Object {
  $hashBytes = [System.Text.Encoding]::UTF8.GetBytes($_)
  $hashString = ($hash.ComputeHash($hashBytes) | ForEach-Object { "{0:X2}" -f $_ }) -join ""
  $hashString
} | Set-Content $outputFile

 Write-Host "Arquivo criado com sucesso: $outputFile"

} else {
  Write-Host "O arquivo não existe: $inputFile"
}