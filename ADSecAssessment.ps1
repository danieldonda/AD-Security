# Assessamento de segurança no Active Directory
# Objetivo: Coletar informações e identificar pontos críticos na segurança do AD
# Autor: Daniel Donda
# Data: 30/01/2023
# Nota: Este script coleta informações sobre o AD e exibe na tela. Não execute em produção sem autorização.

Import-Module ActiveDirectory
Clear-Host
#calcula 180 dias
$date = Get-Date
$180daysAgo = $date.AddDays(-180)


# Display the title
Write-Host "    _    ____    ____                       _ _          "
Write-Host "   / \  |  _ \  / ___|  ___  ___ _   _ _ __(_) |_ _   _  "
Write-Host "  / _ \ | | | | \___ \ / _ \/ __| | | | '__| | __| | | | "
Write-Host " / ___ \| |_| |  ___) |  __/ (__| |_| | |  | | |_| |_| | "
Write-Host "/_/   \_\____/  |____/ \___|\___|\__,_|_|  |_|\__|\__, | "
Write-Host "                                                  |___/  "                                               
Write-Host "AD SECURITY ASSESSMENT 1.0 | "$date -ForegroundColor Green
Write-Host "=========================================================" 
                                                                                                                                                                          

#info sobre as contas(7 itens)
$userspne = Get-ADUser -Filter {(PasswordNeverExpires -eq $true)} -Properties DisplayName,SamAccountName,PasswordLastSet
$usersadmin = Get-ADGroupMember -Identity "Domain Admins" -Recursive | Get-ADUser -Properties DisplayName,SamAccountName
$usersadmin1 = Get-ADGroupMember -Identity "Administrators" -Recursive | Get-ADUser -Properties DisplayName,SamAccountName
$usersdisabled = Get-ADUser -Filter {(Enabled -eq $false)} -Properties DisplayName,SamAccountName,PasswordLastSet
$users180dias = Get-ADUser -Filter {LastLogonTimeStamp -lt $180daysAgo} -Properties DisplayName,SamAccountName,LastLogonTimeStamp
$userssidhistory = Get-ADUser -LDAPFilter '(!sidhistory=*)' -Properties DisplayName,SamAccountName,sidhistory
$AdminsdHolder=  get-aduser -Filter {admincount -gt 0} -Properties adminCount -ResultSetSize $null  
$Guest = Get-ADUser -Filter {SamAccountName -eq "Guest"} -Properties Enabled 
$inativos = Search-ADAccount –AccountInActive –UsersOnly –TimeSpan 180:00:00:00 –ResultPageSize 2000 –ResultSetSize $null | ?{$_.Enabled –eq $True} 


#overview do AD (8 itens)
$Domain = Get-ADDomain
$Forest = Get-ADForest
$DomainName = $Domain.DNSRoot
$ForestFunctionalLevel = $Forest.ForestMode
$UsersCount = (Get-ADUser -Filter * -SearchBase $Domain.DistinguishedName).Count
$ComputersCount = (Get-ADComputer -Filter * -SearchBase $Domain.DistinguishedName).Count
$GroupsCount = (Get-ADGroup -Filter * -SearchBase $Domain.DistinguishedName).Count
$domainControllers = Get-ADDomainController -Filter *
$OUsCount = (Get-ADOrganizationalUnit -Filter * -SearchBase $Domain.DistinguishedName).Count

#Senhas(7 itens)
$passcomp = (Get-ADDefaultDomainPasswordPolicy).ComplexityEnabled  
$passlengh = (Get-ADDefaultDomainPasswordPolicy).MinPasswordLength  
$passhistory = (Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount 
$passblock = (Get-ADDefaultDomainPasswordPolicy).LockoutThreshold
$passdesblock = (Get-ADDefaultDomainPasswordPolicy).LockoutDuration
$passage = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.days 
$passage2 = (Get-ADDefaultDomainPasswordPolicy).MinPasswordAge.days 

#Golden Ticket Attack 
$krbtgt = Get-ADUser -Filter {samAccountName -eq "krbtgt"} -Properties WhenChanged

#DCSync attack Attack 
$reversiblePwd = Get-ADDefaultDomainPasswordPolicy 
$reversiblePwd2 = $reversiblePwd.ReversibleEncryptionEnabled

#Kerberos Delegation / Print Spooler service
$kerbdelegation = Get-ADObject -filter { (UserAccountControl -BAND 0x0080000) -OR (UserAccountControl -BAND 0x1000000) -OR (msDS-AllowedToDelegateTo -like '*') } -prop Name,ObjectClass,PrimaryGroupID,UserAccountControl,ServicePrincipalName,msDS-AllowedToDelegateTo

foreach ($dc in $domainControllers) {
    $spooler = Get-Service -Name "Spooler" -ComputerName $dc.HostName 
     if ($spooler.Status -eq "Running") {
     $spoolerEnabled = $($dc.HostName)
      } else {
     $spoolerDisabled = $($dc.HostName)
  }
}

#Exibe overview do AD
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
Write-Host "Usuários com senha que nunca expira...:" -ForegroundColor white -NoNewLine; Write-Host ""$userspne.Count""  -ForegroundColor Red
Write-Host "Usuários desabilitados................:" -ForegroundColor white -NoNewLine; Write-Host ""$usersdisabled.Count"" -ForegroundColor Red
Write-Host "Usuários sem logon (180 dias..........:" -ForegroundColor white -NoNewLine; Write-Host ""$users180dias.Count"" -ForegroundColor Red
Write-Host "Usuários no grupo Domain Admins.......:" -ForegroundColor white -NoNewLine; Write-Host ""$usersadmin.Count"" -ForegroundColor Red
Write-Host "Usuários no grupo Administrators......:" -ForegroundColor white -NoNewLine; Write-Host ""$usersadmin1.Count"" -ForegroundColor Red
Write-Host "Usuários inativos (180 dias)..........:" -ForegroundColor white -NoNewLine; Write-Host ""$inativos.Count"" -ForegroundColor Red
Write-Host "Usuários com SIDHistory...............:" -ForegroundColor white -NoNewLine; Write-Host ""$userssidhistory.Count"" -ForegroundColor Red
Write-Host "AdminSDHolder.........................:" -ForegroundColor white -NoNewLine; Write-Host ""$AdminsdHolder.Count"" -ForegroundColor Red
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


#exportação de usuários no formato CSV.


$folder = "C:\temp"

if (!(Test-Path -Path $folder)) {
    New-Item -ItemType Directory -Path $folder
    Write-Host "Pasta $folder criada com sucesso." -ForegroundColor Green
} else {
    Write-Host "Pasta $folder já existe."
}

$csvFiles = Get-ChildItem -Path $folder -Filter "*.csv" -Recurse

if ($csvFiles) {
    Write-Host "Arquivos .csv criados com sucesso:" -ForegroundColor Green
    foreach ($file in $csvFiles) {
        Write-Host $file.FullName
    }
} else {
    Write-Host "Não foi possivel gravar os arquivos .csv na pasta $folder" -ForegroundColor Red
}
# Export the results to a CSV file
$userspne | Export-Csv -Path "C:\temp\users-password-never-expire.csv" -NoTypeInformation -Encoding UTF8
$usersadmin | Export-Csv -Path "C:\temp\users-domain-admins.csv" -NoTypeInformation -Encoding UTF8
$usersadmin1 | Export-Csv -Path "C:\temp\users-domain-administrators.csv" -NoTypeInformation -Encoding UTF8
$usersdisabled | Export-Csv -Path "C:\temp\users-disabled.csv" -NoTypeInformation -Encoding UTF8
# $result | Export-Csv -Path "C:\temp\domain-info.csv" -NoTypeInformation -Encoding UTF8
$users180dias | Export-Csv -Path "C:\temp\users-not-logged-on-180-days.csv" -NoTypeInformation -Encoding UTF8
$userssidhistory | Export-Csv -Path "C:\temp\users-sidhistory.csv" -NoTypeInformation -Encoding UTF8
$AdminsdHolder  | Export-Csv -Path "C:\temp\AdminsdHolder.csv" -NoTypeInformation -Encoding UTF8
$kerbdelegation | Export-Csv -Path "C:\temp\Kerbdelegation.csv" -NoTypeInformation -Encoding UTF8
$spoolerEnabled | Export-Csv -Path "C:\temp\PrintSpoolerEnabled.csv" -NoTypeInformation -Encoding UTF8
$inativos | Export-Csv -Path "C:\temp\usuarios-inativos.csv" -NoTypeInformation -Encoding UTF8       
