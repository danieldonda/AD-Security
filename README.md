# AD-Security
Repositório com scripts voltados à segurança do Active Directory com propósito de  documentar e compartilhar as soluções e técnicas utilizadas para aumentar a segurança da infraestrutura de Active Directory além de contribuir para a comunidade de profissionais de segurança. 

## Conteúdo
- [AD-Security-Assesment](#AD-Security-Assesment)
- [HashGenerator](#Hash-Generator)


# AD-Security-Assesment
Script do Powershell para uma rápida visualização de informações criticas de segurança para o Active Directory. 

> Esse script pode auxiliar me caso de comprometimento do Active
> Directory

Realizar um assessment de segurança no Active Directory é importante por várias razões, incluindo:
- Identificação de ameaças: O assessment ajuda a identificar as ameaças e vulnerabilidades existentes no seu ambiente Active Directory, permitindo que você tome medidas para corrigi-las antes que sejam exploradas por atacantes.
- Melhoria da segurança: Ao identificar vulnerabilidades e corrigi-las, você pode melhorar a segurança geral do seu ambiente Active Directory.
- Proteção contra ataques: Ao identificar vulnerabilidades e corrigi-las, você pode proteger o seu ambiente Active Directory contra ataques maliciosos, como ataques de engenharia social, vírus e ransomware.

O assessment de segurança no Active Directory é crucial para garantir que o seu ambiente seja seguro e protegido contra ameaças.

O script apresentará um resumo do seu **Active Directory**

- Nível funcional da floresta     
- Quantidade de usuários     
- Quantidade de computadores
- Quantidade de domain controllers 
- Quantidade de grupos 
- Quantidade de OUs
- Usuários com senha que nunca expira 
- Usuários sem logon (180 dias) 
- Usuários no grupo Domain Admins
- Usuários no grupo Administrators 
- Usuários inativos (180 dias) 
- Usuários com SIDHistory 
- AdminSDHolder 
- Conta Guest Habilitada 
- Politica de senha 

Irá criar uma lista de 10 arquivos CSV com:

- Usuários com senha que nunca  
- Usuários desabilitados 
- Usuários sem logon (180 dias) 
- Usuários no grupo Domain Admins 
- Usuários no grupo Administrators 
- Usuários inativos (180 dias) 
- Admins Usuários AdminSDHolder
- Controladores de domínio com Printer spooler habilitado
- Kerberos Delegation 

Irá gerar também um resumo em TXT e um arquivo contendo as HASHES de todos os arquivos gerados.

*O arquivo CSV permite o uso do PowerBI ou do Excel para gerar gráficos e listas de verificação.*
*Ao importar um arquivo CSV para o PowerBI ou o Excel, você pode usar as funcionalidades de visualização de dados para criar gráficos, tabelas, dashboards e outras formas de representar informações.*


# Destaque

- **GOLDEN TICKET ATTACK** - Exibe quando foi modificada a conta krbtgt
- **DCSYNC ATTACK** - Exibe contas com a criptografia reversivel habiltada
- **PRINT SPOOLER ATTACK** - Exibe Kerberos Delegation e os DCs com Print Spooler Habilitado

![image](https://user-images.githubusercontent.com/16530643/216141192-814fdd3d-34ba-48cd-a3fb-dc95c8a51ff6.png)

## Como usar?

Basta baixar o arquivo e executar com credenciais adminmistrativas em controlador de dominio.

# Mitre Att&ck

## TTPs (Tactics, Techniques and Procedures) listados no MITRE ATT&CK para o ataque **Golden Ticket** 

- T1110.001: Brute Force: Utilização de técnicas de força bruta para adquirir o hash Kerberos do usuário administrador da conta KRBTGT.
- T1559.002: Domain Hierarchy Traversal: Comprometimento da conta KRBTGT para aproveitar a sua capacidade de criar tickets Kerberos válidos para qualquer usuário ou computador em todo o domínio.
- T1558.003: Use of Default Account: Utilização da conta KRBTGT para fornecer autenticação elevada a um invasor.
- T1208: Exploitation of Trusted Relationships: Exploração de relações de confiança, como a autenticação Kerberos, para acessar recursos e dados sensíveis.
- T1212: Exploitation of Vulnerability: Aproveitamento de vulnerabilidades do sistema para obter acesso privilegiado, como a obtenção de hash do KRBTGT.

## TTPs (Tactics, Techniques and Procedures) listados no MITRE ATT&CK para o ataque **DCSync** 

- T1110 - Brute Force
- T1003.001 - Credential Dumping: LSASS Memory
- T1098 - Account Manipulation
- T1003 - Credential Dumping
- T1021 - Remote Services
- T1041 - Exfiltration Over Command and Control Channel

## Os IDs dos TTPs (Tactics, Techniques and Procedures) listados no MITRE ATT&CK que abusam de Kerberos Delegation são:

- T1208: Kerberos Delegation
- T1569: Kerberos Golden Ticket
- T1597: Pass the Ticket
- T1598: Pass the Hash
- T1599: Pass the Key
- T1600: Kerberos Silver Ticket
- T1603: Kerberos Authentication Request Spoofing


# Hash-Generator

Este script usa o .NET Framework para calcular o hash SHA-1 a partir de uma lista de senhas em um arquivo de texto puro.
Ideal para criar um dicionario de senhas que podem ser utilizadas para avaliação de segurança.

# Como usar ?
Defina o arquivo de entrada (arquivo com senhas em texto puro) na variável $inputFile.
Defina o caminho para salvar o arquivo de saida (senhas no formato hash 1) $outputFile.
Neste repositorio deixo disponível um arquivo com as 50 senhas mais usadas no Brasil (senhas-texto-puro.txt) 

![image](https://user-images.githubusercontent.com/16530643/216614970-01732664-047e-4b6c-80e8-46f5eb2db7e3.png)


