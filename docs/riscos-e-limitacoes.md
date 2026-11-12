# Riscos e limitações

Hardening reduz a superfície de ataque; não garante invulnerabilidade. Esta página lista o que pode dar errado ao aplicar os controles e o que o script não cobre.

## Riscos operacionais por controle

| ID | Risco ao aplicar | Mitigação no script | O que fazer se acontecer |
|----|------------------|---------------------|---------------------------|
| 01-04 | Usuários precisam trocar a senha no próximo vencimento; senhas antigas curtas continuam válidas até a troca | Só altera a política, não força troca imediata | Comunicar antes; rollback volta os valores |
| 05-06 | Bloqueio proposital de contas (negação de serviço) por quem conhece o nome de usuário | Limite e duração vêm do perfil; a conta −500 não é bloqueada por padrão | Desmarcar "A conta está bloqueada" em `lusrmgr.msc` ou esperar a duração; revisar o limite com a ATI-PE |
| 07 | Scripts, tarefas agendadas e documentação que usam "Administrador" pelo nome param de funcionar | Renomeia pelo SID, recusa nome em uso, nome vem de aprovação | Rollback renomeia de volta |
| 08 | Algum serviço legado que dependia de Convidado | Só desabilita, não apaga | Rollback reabilita |
| 09 | Programas antigos que esperavam UAC desligado; mudança de `EnableLUA` exige reinício | Marca "reinício necessário" no relatório | Rollback volta os valores e também pede reinício |
| 11, 14 | Mais eventos no log Security (log enche mais rápido) | Só duas subcategorias por controle | Aumentar o tamanho do log (controle 13 aponta) |
| 15 | Aplicação legada que usa SMBv1, Telnet ou PowerShell 2.0 | Só desabilita o que estiver aprovado; `-NoRestart` | Rollback reabilita; pode exigir reinício |
| 10, 12, 13, 16 | — | Somente auditoria: o script não muda nada | — |

## Limitações conhecidas

- **Domínio e GPO**: em máquina de domínio a GPO sobrepõe a política local. O modo Apply é recusado fora de workgroup e controladores de domínio são recusados sempre; nesses casos as mudanças devem ser feitas por GPO.
- **Backup local ≠ snapshot**: o backup cobre só os valores que cada controle altera. Qualquer outra mudança feita na máquina depois da aplicação não é desfeita. O snapshot externo da VM é a recuperação completa.
- **Rollback limitado**: se alguém mudar a mesma configuração entre a aplicação e o rollback, o rollback sobrescreve essa mudança com o valor salvo. Revise antes.
- **Edições do Windows**: a referência é Windows 10/11 Pro ou Windows Server. No Windows 8 ou anterior o script recusa a execução. Recursos opcionais ausentes na edição aparecem como "Ausente".
- **Windows PowerShell 5.1**: é a referência. O PowerShell 7 audita, mas o modo Apply exige o 5.1 (módulo LocalAccounts nativo).
- **Recomendações modernas**: complexidade e rotação obrigatória (02 e 04) seguem o checklist, mas o NIST SP 800-63B-4 recomenda priorizar comprimento e listas de senhas vazadas. O relatório registra a observação.
- **Escopo do checklist**: atualizações do Windows, BitLocker, antivírus, AppLocker/WDAC e LAPS ficaram fora dos 16 itens.
- **Validação**: a CI executa o ciclo completo num Windows Server descartável do GitHub. A validação na VM do laboratório (Windows 10/11 Pro) e a homologação pela ATI-PE continuam pendentes.
