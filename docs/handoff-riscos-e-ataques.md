# Entrega para o grupo de riscos e ataques

Para: Caio Tenório e Tiago Gaspar (relatório dos ataques impedidos).
De: Grupo 2 (automação), a partir do checklist de Rodrigo Campos e Gabriel Cortez.

Esta tabela liga cada controle aos ataques que ele dificulta e aos eventos do Windows que servem de evidência. As técnicas seguem a nomenclatura do MITRE ATT&CK e devem ser conferidas em attack.mitre.org antes de entrar no relatório final.

| ID | Controle | Ataque dificultado | ATT&CK | Evidência no Windows |
|----|----------|--------------------|--------|----------------------|
| 01 | Senha mínima ≥ 12 | Adivinhação e quebra offline de hash | T1110.001, T1110.002 | `net accounts`; política em `relatorio.html` |
| 02 | Complexidade | Senhas de dicionário | T1110.001 | Troca de senha fraca recusada |
| 03 | Histórico ≥ 5 | Reuso de senha já vazada | T1110.004 (credential stuffing) | Troca para senha anterior recusada |
| 04 | Validade ≤ 90 dias | Uso prolongado de credencial roubada | T1078 | `net user <conta>` mostra a expiração |
| 05 | Bloqueio após 5 | Força bruta e password spraying | T1110.001, T1110.003 | 4625 (falhas) seguidos de 4740 (bloqueio) |
| 06 | Bloqueio ≥ 15 min | Força bruta contínua | T1110 | Conta segue bloqueada durante 15 min |
| 07 | Renomear −500 | Ataque à conta padrão pelo nome | T1078.001 | `Get-LocalUser` (SID −500 com outro nome) |
| 08 | Convidado desabilitado | Acesso com conta padrão sem senha | T1078.001 | Logon como Convidado recusado (4625, status 0xC0000072) |
| 09 | UAC elevado | Elevação silenciosa e bypass de UAC | T1548.002 | Prompt na área de trabalho segura |
| 10 | Logon de rede de contas locais (auditoria) | Movimento lateral com a mesma senha local | T1550.002, T1021.002 | Relatório aponta S-1-5-113 ausente; 4624 tipo 3 com conta local |
| 11 | Auditoria de logon | Tentativas sem registro | Apoia detecção de T1110 e T1078 | 4624, 4625 |
| 12 | Firewall e portas (auditoria) | Descoberta e exploração de serviços expostos | T1046, T1021.001, T1210 | Lista de portas em escuta no relatório |
| 13 | Proteção de logs (auditoria) | Limpeza de rastros | T1070.001, T1562.002 | 1102 (Security limpo), 104 (outro log limpo) |
| 14 | Contas e grupos | Persistência por conta nova ou promovida | T1136.001, T1098 | 4720 (conta criada), 4732 (membro adicionado), 4738 |
| 15 | Aplicações e recursos | Exploração de SMBv1 (EternalBlue), downgrade para PowerShell 2.0 | T1210, T1059.001 | Recurso "Disabled" no relatório |
| 16 | Serviços (auditoria) | Escalada por caminho sem aspas, conta de serviço esquecida | T1574.009, T1543.003 | Relatório lista caminhos sem aspas e contas |

## Como gerar as evidências

1. Na VM com snapshot: `.\Main.ps1` (auditoria antes), aplicar com aprovação, `.\Main.ps1` de novo.
2. Para 05/06/11: errar a senha de uma conta de teste 5 vezes e exportar do Visualizador de Eventos os eventos 4625 e 4740 (Logs do Windows → Segurança → Filtrar log atual).
3. Para 14: criar e apagar um usuário de teste e exportar 4720/4726.
4. Anexar `relatorio.html` antes e depois de cada execução.

Não registrar medições ou eficácia que não tenham sido executadas: o que não foi testado fica como pendente no relatório.
