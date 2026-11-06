# Plano de testes em VM Windows

Use uma VM de laboratório isolada e com acesso pelo console. Registre a edição do Windows, o vínculo a domínio, o contexto de privilégio e o identificador do snapshot externo. Mantenha os relatórios em armazenamento restrito.

1. Rode `Main.ps1 -Mode Audit` e revise os 16 resultados. Confira valores observados, esperados, estado do controle e a presença de JSON, CSV, HTML e Markdown na pasta da coleta.
2. Reabra a coleta com `Main.ps1 -Mode Report -OutputDirectory CAMINHO-DA-COLETA`. Confira que o relatório corresponde ao JSON salvo.
3. Rode `Main.ps1 -Mode Apply -ControlIds '01','03' -WhatIf`. Audite novamente para confirmar que os valores das diretivas permaneceram iguais.
4. Em cópias locais dos modelos, autorize os IDs selecionados e registre o escopo, o motivo, o responsável e o snapshot. Execute `Apply` com `-ConfirmApply` em uma sessão elevada. Registre o backup, o resultado de cada aplicação e o estado após a alteração.
5. Rode `Verify` e compare os estados. Repita uma aplicação autorizada no mesmo estado para conferir se o programa evita mudanças redundantes.
6. Para 05 e 06, avalie a coerência entre duração, zeragem e limite. Qualquer teste prático de bloqueio deve usar uma conta descartável da VM. Para 07, teste outra conta administrativa no console antes de autorizar. Para 09, confira o consentimento no console após eventual reinicialização autorizada.
7. Para 10, 12, 13 e 16, revise o inventário com o responsável. Registre fluxos remotos, regras e portas, permissões de logs ou dependências de serviços de acordo com o ID. A verificação prática de conectividade deve usar uma origem autorizada.
8. Para 11 e 14, compare as subcategorias de auditoria e consulte somente os metadados necessários de eventos autorizados. Revise membros e direitos do ID 14 separadamente.
9. Para 15, valide as dependências e as duas listas de aprovação antes de desabilitar um recurso opcional. Teste os serviços afetados e revise o indicador de reinício. Planeje retorno pelo hipervisor.
10. Para o rollback de um ID suportado, teste tanto a restauração com estado pós-aplicação correspondente quanto o bloqueio após uma mudança externa documentada. Confira que o backup pertence à mesma VM e que a autorização permite rollback.
11. Registre os IDs e os cenários efetivamente testados. Guarde somente as evidências necessárias, com dados pessoais minimizados.

Para demonstrar o formato do relatório sem consultar o sistema, rode `Main.ps1 -Demo`. Os resultados dessa execução são fictícios.
