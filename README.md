
# AD-Security-Assessment
Script do Powershell para uma rápida visualização de informações criticas de segurança para o Active Directory. 

> Esse script pode auxiliar me caso de comprometimento do Active
> Directory

Realizar um assessment de segurança no Active Directory é importante por várias razões, incluindo:
- Identificação de ameaças: O assessment ajuda a identificar as ameaças e vulnerabilidades existentes no seu ambiente Active Directory, permitindo que você tome medidas para corrigi-las antes que sejam exploradas por atacantes.
- Melhoria da segurança: Ao identificar vulnerabilidades e corrigi-las, você pode melhorar a segurança geral do seu ambiente Active Directory.
- Proteção contra ataques: Ao identificar vulnerabilidades e corrigi-las, você pode proteger o seu ambiente Active Directory contra ataques maliciosos, como ataques de engenharia social, vírus e ransomware.

O assessment de segurança no Active Directory é crucial para garantir que o seu ambiente seja seguro e protegido contra ameaças.

O Script exibe:

- Nível funcional da floresta     
- Quantidade de usuários     
- Quantidade de computadores
- Quantidade de domain controllers 
- Quantidade de grupos 
- Quantidade de OUs
- Usuários com senha que nunca expira *(exibe a quantidade e gera um csv com a lista de objetos)*
- Usuários sem logon (180 dias) *(exibe a quantidade e gera um csv com a lista de objetos)*
- Usuários no grupo Domain Admins *(exibe a quantidade e gera um csv com a lista de objetos)*
- Usuários no grupo Administrators *(exibe a quantidade e gera um csv com a lista de objetos)*
- Usuários inativos (180 dias) *(exibe a quantidade e gera um csv com a lista de objetos)*
- Usuários com SIDHistory *(exibe a quantidade e gera um csv com a lista de objetos)*
- AdminSDHolder *(exibe a quantidade e gera um csv com a lista de objetos)*
- Conta Guest Habilitada - *Apenas exibe na tela* 
- Politica de senha - *Apenas exibe na tela*

*O arquivo CSV permite o uso do PowerBI ou do Excel para gerar gráficos e listas de verificação.*
*Ao importar um arquivo CSV para o PowerBI ou o Excel, você pode usar as funcionalidades de visualização de dados para criar gráficos, tabelas, dashboards e outras formas de representar informações.*


# Destaque

- **GOLDEN TICKET ATTACK** - Exibe quando foi modificada a conta krbtgt
- **DCSYNC ATTACK** - Exibe contas com a criptografia reversivel habiltada
- **PRINT SPOOLER ATTACK** - Exibe Kerberos Delegation e os DCs com Print Spooler Habilitado

![image](https://user-images.githubusercontent.com/16530643/215624922-d7163079-932c-467e-8155-16e12fbde82f.png)


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

# Version History
Version 1.1
Janeiro de 2023
Otimização do código e suas variaveis.
Geração de resumo em txt 
Geração de hash dos arquivos gerados (para uso como evidencia de ações de correção em incidentes)


Version 1.0
Janeiro de 2023, versão inicial
