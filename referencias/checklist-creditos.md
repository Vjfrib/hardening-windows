# Checklist de origem

Os 16 controles automatizados aqui vêm do documento **"Checklist de Hardening Windows · Contas e Políticas de Acesso"**, elaborado por **Rodrigo Campos** e **Gabriel Cortez** na frente de checklist do projeto de extensão (UPE/POLI, Sistemas Operacionais 2026.2, Prof.ª Tarciana Dias da Silva, com interlocução da ATI-PE).

Divisão das frentes:

1. Checklist de assertivas: Rodrigo Campos e Gabriel Cortez.
2. Automação por script e documentação: Grupo 2, Sofia Queiroz, Mateus Cunha e Vinícius Ribeiro (este repositório).
3. Relatório de riscos e ataques impedidos: Caio Tenório e Tiago Gaspar (ver [docs/handoff-riscos-e-ataques.md](../docs/handoff-riscos-e-ataques.md)).

## Assertivas cobertas

| ID | Assertiva |
|----|-----------|
| 01 | Comprimento mínimo de senha de 12 caracteres |
| 02 | Complexidade de senha habilitada |
| 03 | Histórico de pelo menos 5 senhas |
| 04 | Validade máxima de 90 dias |
| 05 | Bloqueio da conta após 5 tentativas inválidas |
| 06 | Duração do bloqueio de pelo menos 15 minutos |
| 07 | Renomear a conta Administrador (SID −500) |
| 08 | Desabilitar a conta Convidado (SID −501) |
| 09 | UAC no nível elevado, com área de trabalho segura |
| 10 | Restringir logon de rede de contas locais |
| 11 | Auditoria de logon (sucesso e falha) |
| 12 | Firewall ativo e somente portas necessárias |
| 13 | Proteção dos logs |
| 14 | Revisão de usuários e grupos |
| 15 | Remoção de aplicações e recursos desnecessários |
| 16 | Revisão de serviços e contas de serviço |

O PDF original do checklist pertence aos autores e pode ser adicionado nesta pasta por eles.
