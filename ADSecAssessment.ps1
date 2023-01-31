#------------------------------------------------------------------------------------------------------------#
# Assessment de segurança no Active Directory
# Objetivo: Coletar informações e identificar pontos críticos na segurança do AD
# Autor: Daniel Donda
# Data: 30/01/2023
# Nota: Este script coleta informações sobre o AD e exibe na tela. Não execute em produção sem autorização.
#------------------------------------------------------------------------------------------------------------#


# ------------------------------- #
# Variaveis e funções do scripts  #
# ------------------------------- #

Import-Module ActiveDirectory
Clear-Host
#calcula 180 dias
$date = Get-Date
$180daysAgo = $date.AddDays(-180)
$folder = "C:\temp"
if (!(Test-Path -Path $folder)) {
    New-Item -ItemType Directory -Path $folder
    Write-Host "Pasta $folder criada com sucesso." -ForegroundColor Green
} else {
    Write-Host "Pasta $folder já existe."
}

# Exibe o nome do script
Write-Host "    _    ____    ____                       _ _          "
Write-Host "   / \  |  _ \  / ___|  ___  ___ _   _ _ __(_) |_ _   _  "
Write-Host "  / _ \ | | | | \___ \ / _ \/ __| | | | '__| | __| | | | "
Write-Host " / ___ \| |_| |  ___) |  __/ (__| |_| | |  | | |_| |_| | "
Write-Host "/_/   \_\____/  |____/ \___|\___|\__,_|_|  |_|\__|\__, | "
Write-Host "                                                  |___/  "                                               
Write-Host "AD SECURITY ASSESSMENT 1.1 | "$date -ForegroundColor Green
Write-Host "=========================================================" 

#------------------------------------------------#
# Variaveis de coleta de informações sobre o AD  #
#------------------------------------------------#
$Domain = Get-ADDomain
$Forest = Get-ADForest
$DomainName = $Domain.DNSRoot
$ForestFunctionalLevel = $Forest.ForestMode
$UsersCount = (Get-ADUser -Filter * -SearchBase $Domain.DistinguishedName).Count
$ComputersCount = (Get-ADComputer -Filter * -SearchBase $Domain.DistinguishedName).Count
$GroupsCount = (Get-ADGroup -Filter * -SearchBase $Domain.DistinguishedName).Count
$domainControllers = Get-ADDomainController -Filter *
$OUsCount = (Get-ADOrganizationalUnit -Filter * -SearchBase $Domain.DistinguishedName).Count

                                                                                                                                                                          
#-----------------------------------------------------#
# variaveis de coleta de informações sobre as contas  #
#-----------------------------------------------------#
$userspne = Get-ADUser -Filter {(PasswordNeverExpires -eq $true)} -Properties DisplayName,SamAccountName,PasswordLastSet
$tuserspne = $userspne.Count

$usersadmin = Get-ADGroupMember -Identity "Domain Admins" -Recursive | Get-ADUser -Properties DisplayName,SamAccountName
$tusersadmin = $usersadmin.count 

$usersadmin1 = Get-ADGroupMember -Identity "Administrators" -Recursive | Get-ADUser -Properties DisplayName,SamAccountName
$tusersadmin1 = $usersadmin1.count
 
$usersdisabled = Get-ADUser -Filter {(Enabled -eq $false)} -Properties DisplayName,SamAccountName,PasswordLastSet
$tusersdisabled = $usersdisabled.Count


$users180dias = Get-ADUser -Filter {LastLogonTimeStamp -lt $180daysAgo} -Properties DisplayName,SamAccountName,LastLogonTimeStamp
$tusers180dias = $users180dias.Count


$userssidhistory = Get-ADUser -LDAPFilter '(!sidhistory=*)' -Properties DisplayName,SamAccountName,sidhistory
$tuserssidhistory = $userssidhistory.count

$AdminsdHolder=  get-aduser -Filter {admincount -gt 0} -Properties adminCount -ResultSetSize $null  

$tAdminsdHolder= $AdminsdHolder.Count

$Guest = Get-ADUser -Filter {SamAccountName -eq "Guest"} -Properties Enabled 

$inativos = Search-ADAccount –AccountInActive –UsersOnly –TimeSpan 180:00:00:00 –ResultPageSize 2000 –ResultSetSize $null | ?{$_.Enabled –eq $True} 
$tinativos = $inativos.Count
#--------------------------------------------------------------------#
# Variaveis de coleta de informações sobre a politica de senha do AD #
#--------------------------------------------------------------------#
$passcomp = (Get-ADDefaultDomainPasswordPolicy).ComplexityEnabled  
$passlengh = (Get-ADDefaultDomainPasswordPolicy).MinPasswordLength  
$passhistory = (Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount 
$passblock = (Get-ADDefaultDomainPasswordPolicy).LockoutThreshold
$passdesblock = (Get-ADDefaultDomainPasswordPolicy).LockoutDuration
$passage = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.days 
$passage2 = (Get-ADDefaultDomainPasswordPolicy).MinPasswordAge.days 

#-----------------------------#
# ATAQUES AO ACTIVE DIRECTORY #
#-----------------------------#

# variaveis de coleta de informações sobre o ataque Golden Ticket.
$krbtgt = Get-ADUser -Filter {samAccountName -eq "krbtgt"} -Properties WhenChanged

# # variaveis de coleta de informações sobre o ataque DCSync.
$reversiblePwd = Get-ADDefaultDomainPasswordPolicy 
$reversiblePwd2 = $reversiblePwd.ReversibleEncryptionEnabled

# Variaveis de coleta de informações sobre Kerberos Delegation / Print Spooler service
$kerbdelegation = Get-ADObject -filter { (UserAccountControl -BAND 0x0080000) -OR (UserAccountControl -BAND 0x1000000) -OR (msDS-AllowedToDelegateTo -like '*') } -prop Name,ObjectClass,PrimaryGroupID,UserAccountControl,ServicePrincipalName,msDS-AllowedToDelegateTo

foreach ($dc in $domainControllers) {
    $spooler = Get-Service -Name "Spooler" -ComputerName $dc.HostName 
     if ($spooler.Status -eq "Running") {
     $spoolerEnabled = $($dc.HostName)
      } else {
     $spoolerDisabled = $($dc.HostName)
  }
}

# ----------------------------------------------- #
# Apresentação na tela das informações coletadas. #
# ----------------------------------------------- #

Write-Host "---------------------------------------------------------" 
Write-Host "RESUMO DAS INFORMAÇÕES DO ACTIVE DIRECTORY" -ForegroundColor Yellow
Write-Host "---------------------------------------------------------" 
Write-Host "Nome do domínio.......................:" -ForegroundColor white -NoNewLine; Write-Host " $domainName" -ForegroundColor Green 
Write-Host "Nível funcional da floresta...........:" -ForegroundColor white -NoNewLine; Write-Host " $ForestFunctionalLevel" -ForegroundColor Green  
Write-Host "Quantidade de usuários................:" -ForegroundColor white -NoNewLine; Write-Host " $usersCount" -ForegroundColor Green
Write-Host "Quantidade de computadores............:" -ForegroundColor white -NoNewLine; Write-Host " $computersCount" -ForegroundColor Green
Write-Host "Quantidade de domain controllers......:" -ForegroundColor white -NoNewLine; Write-Host " $($domainControllers.name.ToString().count) " -ForegroundColor Green 
Write-Host "Quantidade de grupos..................:" -ForegroundColor white -NoNewLine; Write-Host " $GroupsCount" -ForegroundColor Green
Write-Host "Quantidade de OUs.....................:" -ForegroundColor white -NoNewLine; Write-Host " $OUsCount" -ForegroundColor Green
Write-Host "---------------------------------------------------------" 
Write-Host "INFORMAÇÕES DE OBJETOS (CSV)" -ForegroundColor Yellow
Write-Host "---------------------------------------------------------" 
Write-Host "Usuários com senha que nunca expira...:" -ForegroundColor white -NoNewLine; Write-Host ""$tuserspne""  -ForegroundColor Red
Write-Host "Usuários desabilitados................:" -ForegroundColor white -NoNewLine; Write-Host ""$tusersdisabled"" -ForegroundColor Red
Write-Host "Usuários sem logon (180 dias..........:" -ForegroundColor white -NoNewLine; Write-Host ""$tusers180dias"" -ForegroundColor Red
Write-Host "Usuários no grupo Domain Admins.......:" -ForegroundColor white -NoNewLine; Write-Host ""$tusersadmin"" -ForegroundColor Red
Write-Host "Usuários no grupo Administrators......:" -ForegroundColor white -NoNewLine; Write-Host ""$tusersadmin1"" -ForegroundColor Red
Write-Host "Usuários inativos (180 dias)..........:" -ForegroundColor white -NoNewLine; Write-Host ""$tinativos"" -ForegroundColor Red
Write-Host "Usuários com SIDHistory...............:" -ForegroundColor white -NoNewLine; Write-Host ""$tuserssidhistory"" -ForegroundColor Red
Write-Host "AdminSDHolder.........................:" -ForegroundColor white -NoNewLine; Write-Host ""$tAdminsdHolder"" -ForegroundColor Red
Write-Host "Conta Guest Habilitada................:" -ForegroundColor white -NoNewLine; Write-Host " $($Guest.name.ToString().count)" -ForegroundColor Red
Write-Host "---------------------------------------------------------" 
Write-Host "POLITICA DE SENHA DO DOMINIO" -ForegroundColor Yellow
Write-Host "---------------------------------------------------------" 
Write-Host "Politica de senha - Complexidade......: "-ForegroundColor white -NoNewLine; Write-Host "$passcomp" -ForegroundColor Green
Write-Host "Politica de senha - Tamanho da senha..: "-ForegroundColor white -NoNewLine; Write-Host "$passlengh" -ForegroundColor Green
Write-Host "Politica de senha - Historico.........: "-ForegroundColor white -NoNewLine; Write-Host "$passhistory" -ForegroundColor Green
Write-Host "Politica de senha - Tentativas erradas: "-ForegroundColor white -NoNewLine; Write-Host "$passblock" -ForegroundColor Green
Write-Host "Politica de senha - Tempo de bloqueio.: "-ForegroundColor white -NoNewLine; Write-Host "$passdesblock" -ForegroundColor Green
Write-Host "Politica de senha - Idade maxima......: "-ForegroundColor white -NoNewLine; Write-Host "$passage" -ForegroundColor Green
Write-Host "Politica de senha - Idade Minima......: "-ForegroundColor white -NoNewLine; Write-Host "$passage2" -ForegroundColor Green
Write-Host "---------------------------------------------------------" 
Write-Host "GOLDEN TICKET ATTACK" -ForegroundColor Yellow
Write-Host "---------------------------------------------------------" 
Write-Host "A conta krbtgt foi modificada em:..:" -ForegroundColor white -NoNewLine; Write-Host " $($krbtgt.WhenChanged.ToString())" -ForegroundColor Green 
Write-Host "---------------------------------------------------------" 
Write-Host "DCSYNC ATTACK" -ForegroundColor Yellow
Write-Host "---------------------------------------------------------" 
Write-Host "Criptografia reversivel habiltada.....:" -ForegroundColor white -NoNewLine; Write-Host "$reversiblePwd2" -ForegroundColor Green 
Write-Host "---------------------------------------------------------" 
Write-Host "PRINT SPOOLER ATTACK" -ForegroundColor Yellow
Write-Host "---------------------------------------------------------" 
Write-Host "Kerberos Delegation...................:" -ForegroundColor white -NoNewLine; Write-Host " $($kerbdelegation.name.ToString().count)" -ForegroundColor Red
Write-Host "DCs com Print Spooler Habilitado......:" -ForegroundColor White -NoNewline; Write-Host ""$spoolerEnabled.count"" -ForegroundColor Red
Write-Host "---------------------------------------------------------" 

New-Item $folder/ADSecAssessment-Overview.txt -type file -Force >null

$bloco = @("
---------------------------------------------------------  
RESUMO DAS INFORMAÇÕES DO ACTIVE DIRECTORY                 
--------------------------------------------------------- 
 Nome do domínio.......................: $domainName         
 Nível funcional da floresta...........: $ForestFunctionalLevel 
 Quantidade de usuários................: $usersCount 
 Quantidade de computadores............: $computersCount 
 Quantidade de domain controllers......: $domainControllers
 Quantidade de grupos..................: $GroupsCount 
 Quantidade de OUs.....................: $OUsCount 
 ---------------------------------------------------------  
 INFORMAÇÕES DE OBJETOS (CSV) 
 --------------------------------------------------------- 
 Usuários com senha que nunca expira...: $tuserspne
 Usuários desabilitados................: $tusersdisabled
 Usuários sem logon (180 dias..........: $tusers180dias
 Usuários no grupo Domain Admins.......: $tusersadmin
 Usuários no grupo Administrators......: $tusersadmin1
 Usuários inativos (180 dias)..........: $tinativos 
 Usuários com SIDHistory...............: $tuserssidhistory
 AdminSDHolder.........................: $tAdminsdHolder
 Conta Guest Habilitada................: $Guest
 ---------------------------------------------------------  
 POLITICA DE SENHA DO DOMINIO 
 ---------------------------------------------------------  
 Politica de senha - Complexidade......: $passcomp 
 Politica de senha - Tamanho da senha..: $passlengh 
 Politica de senha - Historico.........: $passhistory 
 Politica de senha - Tentativas erradas: $passblock 
 Politica de senha - Tempo de bloqueio.: $passdesblock 
 Politica de senha - Idade maxima......: $passage 
 Politica de senha - Idade Minima......: $passage2 
 --------------------------------------------------------- 
 GOLDEN TICKET ATTACK  
 ---------------------------------------------------------  
 A conta krbtgt foi modificada em:..:  $($krbtgt.WhenChanged.ToString()) 
 ---------------------------------------------------------  
 DCSYNC ATTACK  
 --------------------------------------------------------- 
 Criptografia reversivel habiltada.....: $reversiblePwd2   
 --------------------------------------------------------- 
 PRINT SPOOLER ATTACK 
 --------------------------------------------------------- 
 Kerberos Delegation...................:  $($kerbdelegation.name.ToString().count) 
 DCs com Print Spooler Habilitado......: $spoolerEnabled.count 
 --------------------------------------------------------- 

")

$bloco | Add-Content $folder/ADSecAssessment-Overview.txt

# ----------------------------------------- #
# Exportação de informações no formato CSV. #
# ----------------------------------------- #
$userspne | Export-Csv -Path "C:\temp\users-password-never-expire.csv" -NoTypeInformation -Encoding UTF8
$usersadmin | Export-Csv -Path "C:\temp\users-domain-admins.csv" -NoTypeInformation -Encoding UTF8
$usersadmin1 | Export-Csv -Path "C:\temp\users-domain-administrators.csv" -NoTypeInformation -Encoding UTF8
$usersdisabled | Export-Csv -Path "C:\temp\users-disabled.csv" -NoTypeInformation -Encoding UTF8
$users180dias | Export-Csv -Path "C:\temp\users-not-logged-on-180-days.csv" -NoTypeInformation -Encoding UTF8
$userssidhistory | Export-Csv -Path "C:\temp\users-sidhistory.csv" -NoTypeInformation -Encoding UTF8
$AdminsdHolder  | Export-Csv -Path "C:\temp\AdminsdHolder.csv" -NoTypeInformation -Encoding UTF8
$kerbdelegation | Export-Csv -Path "C:\temp\Kerbdelegation.csv" -NoTypeInformation -Encoding UTF8
$spoolerEnabled | Export-Csv -Path "C:\temp\PrintSpoolerEnabled.csv" -NoTypeInformation -Encoding UTF8
$inativos | Export-Csv -Path "C:\temp\usuarios-inativos.csv" -NoTypeInformation -Encoding UTF8     


# Validação de arquivos CSV.

$csvFiles = Get-ChildItem -Path $folder -Filter "*.csv" -Recurse

if ($csvFiles) {
    Write-Host  $csvFiles.count "Arquivos .csv criados com sucesso" -ForegroundColor Green
    foreach ($file in $csvFiles) {
       # Write-Host $file.count
    }
} else {
    Write-Host "Não foi possivel gravar os arquivos .csv na pasta $folder" -ForegroundColor Red
}
 
# Geração de hash 

$arquivos = Get-ChildItem $folder

foreach ($arquivo in $arquivos) {
  $hash = (Get-FileHash $arquivo.FullName).Hash
  Write-host "$($arquivo.Name) - $hash" *>> $folder/ADSecAssessment-Hash.txt
}
Write-Host "Hashes criado com sucesso" -ForegroundColor Green
