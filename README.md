# AD-Security-Assessment
Script do Powershell para uma rápida visualização de informações criticas de segurança para o Active Directory. 

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
- Usuários com senha que nunca expira (exibe a quatidade e gera um csv com a lista de objetos)
- Usuários sem logon (180 dias) (exibe a quatidade e gera um csv com a lista de objetos)
- Usuários no grupo Domain Admins (exibe a quatidade e gera um csv com a lista de objetos)
- Usuários no grupo Administrators (exibe a quatidade e gera um csv com a lista de objetos)
- Usuários inativos (180 dias)(exibe a quatidade e gera um csv com a lista de objetos)
- Usuários com SIDHistory (exibe a quatidade e gera um csv com a lista de objetos)
- AdminSDHolder (exibe a quatidade e gera um csv com a lista de objetos)
- Conta Guest Habilitada - Apenas exibe na tela 
- Politica de senha - Apenas exibe na tela

# Destaque
- GOLDEN TICKET ATTACK - Exibe quando foi modificada a conta krbtgt
- DCSYNC ATTACK - Exibe contas com a criptografia reversivel habiltada
- PRINT SPOOLER ATTACK - Exite Kerberos Delegation e os DCs com Print Spooler Habilitado

![image](https://user-images.githubusercontent.com/16530643/215624922-d7163079-932c-467e-8155-16e12fbde82f.png)
