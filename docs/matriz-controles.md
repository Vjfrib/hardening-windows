# Matriz dos 16 controles

Cada linha liga a assertiva do checklist (Rodrigo Campos e Gabriel Cortez) ao que o script audita, ao que ele pode aplicar, ao conceito de Sistemas Operacionais envolvido e ao risco reduzido. Os valores esperados vêm do perfil [scripts/config/perfil-academico.example.json](../scripts/config/perfil-academico.example.json).

Legenda de tipo: **A** aplicável com aprovação · **AU** somente auditoria.

## Autenticação (01 a 06)

Todos usam a política de segurança local, lida com `secedit /export` e alterada com `secedit /configure` usando um modelo `.inf` temporário que contém **somente** a chave do controle. Depois de aplicar, o script relê a política e confirma o valor.

| ID | Tipo | Assertiva | Auditoria (Get) | Aplicação (Set) | Rollback | Conceito de SO | Risco reduzido |
|----|------|-----------|-----------------|-----------------|----------|----------------|----------------|
| 01 | A | Senha com no mínimo 12 caracteres | `MinimumPasswordLength` ≥ 12 | Define 12 | Volta ao valor salvo | A base de políticas (SAM/LSA) persiste as regras de autenticação | Adivinhação e quebra offline de senhas curtas |
| 02 | A | Complexidade habilitada | `PasswordComplexity` = 1 | Habilita | Volta ao valor salvo | Filtro de senha da LSA (3 de 4 classes, sem o nome da conta) | Senhas triviais |
| 03 | A | Lembrar ao menos 5 senhas | `PasswordHistorySize` ≥ 5 | Define 5 | Volta ao valor salvo | SAM guarda hashes das senhas anteriores | Reuso de senha vazada |
| 04 | A | Validade máxima de 90 dias | `MaximumPasswordAge` entre 1 e 90 (−1 = nunca expira) | Define 90 | Volta ao valor salvo | SAM registra a última troca e força a troca ao vencer | Senha comprometida usada por tempo indefinido |
| 05 | A | Bloquear após 5 tentativas | `LockoutBadCount` entre 1 e 5 | Define 5 e janela `ResetLockoutCount` = 15 (ajusta a duração se ela for menor que a janela) | Volta os três valores | LSA conta falhas por conta | Força bruta e password spraying; atenção à negação de serviço |
| 06 | A | Bloqueio de pelo menos 15 min | `LockoutDuration` ≥ 15 (−1 = até o administrador liberar) | Define 15 | Volta ao valor salvo | Conta bloqueada fica indisponível até expirar | Força bruta contínua |

Observações: em máquina de domínio a GPO prevalece, por isso o modo Apply é recusado fora de workgroup. Recomendações modernas (NIST SP 800-63B-4) preferem comprimento e lista de senhas vazadas a complexidade e rotação; o perfil segue o checklist e o relatório registra a observação.

## Identidades e acesso (07 a 10)

| ID | Tipo | Assertiva | Auditoria (Get) | Aplicação (Set) | Rollback | Conceito de SO | Risco reduzido |
|----|------|-----------|-----------------|-----------------|----------|----------------|----------------|
| 07 | A | Renomear a conta Administrador | Conta cujo SID termina em −500: nome, habilitada, último logon | `Rename-LocalUser -SID` para `Accounts.AdministratorNewName`; recusa nome vazio, padrão, inválido ou já usado | Renomeia de volta, conferindo o SID | O SID identifica a conta; o nome é rótulo | Ataques pelo nome conhecido (medida complementar: o SID continua −500) |
| 08 | A | Desabilitar Convidado | Conta −501 habilitada? | `Disable-LocalUser -SID` | Reabilita se estava habilitada | Identidade sem senha conhecida; desabilitada, a LSA recusa o logon | Acesso anônimo de fato |
| 09 | A | UAC elevado | `EnableLUA` = 1, `ConsentPromptBehaviorAdmin` = 2, `PromptOnSecureDesktop` = 1 | Grava só os valores divergentes; marca reinício se mudar `EnableLUA` | Volta cada valor (ou remove o que não existia) | Token filtrado x token completo; área de trabalho segura isola o prompt | Elevação silenciosa por malware |
| 10 | AU | Restringir logon de rede de contas locais | `SeDenyNetworkLogonRight` com S-1-5-113/114, `SeNetworkLogonRight`, `LocalAccountTokenFilterPolicy` | Nenhuma | — | Direitos de usuário decidem quem recebe token pela rede | Movimento lateral com a mesma senha local (pass-the-hash) |

Por que 10 é só auditoria: negar logon de rede a contas locais corta compartilhamentos e administração remota; a exceção precisa ser definida pela ATI-PE.

## Rastreabilidade (11 a 14)

Auditoria usa `auditpol` sempre pelo **GUID** da subcategoria, porque o nome muda com o idioma do Windows ("Logon" vira "Fazer logon").

| ID | Tipo | Assertiva | Auditoria (Get) | Aplicação (Set) | Rollback | Conceito de SO | Risco reduzido |
|----|------|-----------|-----------------|-----------------|----------|----------------|----------------|
| 11 | A | Auditar logon com sucesso e falha | Logon `{0CCE9215-…}` = 3; Bloqueio de conta `{0CCE9217-…}` inclui falha; `SCENoApplyLegacyAuditPolicy` | Habilita só essas duas subcategorias (combina com o que já existia) | Volta os valores salvos | O serviço de eventos registra as decisões de autenticação conforme a política | Tentativas sem registro. Eventos 4624, 4625 |
| 12 | AU | Firewall ativo e só portas necessárias | Perfis Domain/Private/Public, entrada padrão, portas TCP/UDP em escuta com processo, portas de administração remota (22, 135, 445, 3389, 5985, 5986) | Nenhuma | — | Firewall filtra a pilha de rede; porta identifica o serviço | Exposição desnecessária e movimento lateral |
| 13 | AU | Proteger os logs | ACL de `%SystemRoot%\System32\winevt\Logs`, canais Security/System (habilitado, tamanho, modo, SDDL), limpezas recentes (1102, 104) | Nenhuma | — | ACL limita quem grava ou apaga os `.evtx` | Limpeza de rastros |
| 14 | A (parcial) | Revisar usuários e grupos | Contas locais (senha obrigatória, nunca expira, nunca usou), membros de Administradores, Área de Trabalho Remota, Operadores de Backup, Gerenciamento Remoto, direitos sensíveis (`SeDebugPrivilege` etc.) | Só habilita Gerenciamento de conta de usuário `{0CCE9235-…}` e de grupo `{0CCE9237-…}`; não mexe em contas nem grupos | Volta os valores salvos | Grupos e direitos entram no token | Persistência por conta nova ou promovida. Eventos 4720, 4732, 4738, 4740 |

## Superfície (15 e 16)

| ID | Tipo | Assertiva | Auditoria (Get) | Aplicação (Set) | Rollback | Conceito de SO | Risco reduzido |
|----|------|-----------|-----------------|-----------------|----------|----------------|----------------|
| 15 | A (parcial) | Remover aplicações e recursos desnecessários | Recursos candidatos (`SMB1Protocol`, `TelnetClient`, `TFTP`, `MicrosoftWindowsPowerShellV2Root`) e aplicações instaladas (registro) | `Disable-WindowsOptionalFeature -NoRestart` só em recurso presente, habilitado **e** listado em `Features.ApprovedToDisable`; não desinstala aplicações | Reabilita os recursos desabilitados | Cada recurso traz binários, serviços e portas | Protocolos legados (SMBv1/EternalBlue), downgrade para PowerShell 2.0 |
| 16 | AU | Revisar serviços e contas de serviço | Serviços com conta fora das internas, caminho sem aspas e com espaço, serviços da lista de revisão ativos (com dependentes) | Nenhuma | — | SCM inicia cada serviço com a conta de `StartName` | Escalada por caminho sem aspas, credenciais de serviço esquecidas |

## Pendências com a ATI-PE

| Campo do perfil | Controle | Decisão necessária |
|-----------------|----------|--------------------|
| `Accounts.AdministratorNewName` | 07 | Nome padrão para a conta −500 |
| `Accounts.ApprovedAdministrators` | 14 | Quem pode ser administrador local |
| `Firewall.AllowedListeningPorts` | 12 | Portas permitidas por tipo de máquina |
| `Features.ApprovedToDisable` | 15 | Recursos que podem ser desabilitados |
| `Services.ReviewIfRunning` | 16 | Serviços proibidos e contas de serviço aprovadas |
| Coletor central de logs | 13 | Para onde os eventos vão (proteção definitiva contra limpeza local) |
