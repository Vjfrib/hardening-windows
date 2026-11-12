# Roteiro de fala · Hardening Windows

Apresentação: [Apresentacao_Hardening_Windows_Grupo2.pdf](Apresentacao_Hardening_Windows_Grupo2.pdf) (15 slides; o 14 não está na versão final).
Duração estimada: 12 a 14 minutos. Em cada slide, **Fala** é o que dizer; **Apoio** é orientação para quem apresenta.

---

## Slide 01 · Hardening Windows

**Fala.** Boa tarde. Somos o Grupo 2, Sofia, Mateus e Vinícius, e o nosso trabalho é a automação de hardening do Windows. Hardening é o conjunto de ajustes que reduz a superfície de ataque de um sistema operacional: menos portas abertas, contas mais protegidas, mais registro do que acontece. A ideia aqui foi transformar um checklist de 16 controles em scripts que primeiro mostram o estado da máquina e só depois, com autorização, mudam alguma coisa.

**Apoio.** Falar devagar. Apontar o subtítulo "segura e rastreável", que é o fio da apresentação.

## Slide 02 · Três frentes, responsabilidades distintas

**Fala.** O projeto de extensão com a ATI-PE foi dividido em três frentes. O Rodrigo e o Gabriel definiram o checklist e as justificativas de cada controle. A nossa frente pega esse checklist e transforma em auditoria e aplicação controlada. E o Caio e o Tiago recebem a nossa tabela de controles e as evidências para escrever o relatório de riscos e ataques. Essa divisão foi proposta na interlocução com a ATI-PE e aceita pela professora.

**Apoio.** Deixar claro que o checklist não é nosso; nós automatizamos.

## Slide 03 · Segurança precisa preservar os serviços

**Fala.** Antes de mudar qualquer coisa, a gente precisou lembrar que segurança não pode derrubar o serviço. Um firewall mal configurado corta a administração remota. Uma política de bloqueio agressiva vira negação de serviço. A versão e a edição do Windows mudam os recursos disponíveis, e uma GPO de domínio pode sobrescrever o que a gente aplica localmente. E toda mudança precisa de um responsável, uma aprovação e uma evidência que permita voltar atrás. Por isso: aplicar com segurança exige conhecer o cenário da VM.

## Slide 04 · Objetivo: conhecer, mudar com controle e comprovar

**Fala.** O objetivo tem três verbos. Conhecer: auditar os 16 IDs e comparar o estado observado com o perfil acadêmico. Controlar: aplicar somente o que foi implementado, aprovado e protegido por backup. Comprovar: verificar de novo depois, exportar os resultados e registrar os limites da recuperação. O laboratório proposto é Windows 10 ou 11 Pro, ou Windows Server compatível. Em Windows 8 ou mais antigo o script se recusa a rodar.

## Slide 05 · Visão geral: exatamente 16 controles

**Fala.** São exatamente 16 controles, em quatro grupos. Autenticação, de 01 a 06: senha mínima de 12, complexidade, histórico de 5, validade de até 90 dias, bloqueio após 5 tentativas e bloqueio de pelo menos 15 minutos. Identidades e acesso, de 07 a 10: renomear o Administrador, que é a conta com SID terminado em 500; desabilitar o Convidado, SID 501; UAC elevado; e logon de rede de contas locais. Rastreabilidade, de 11 a 14: auditoria de logon, firewall e portas, proteção de logs, contas e grupos. E superfície, 15 e 16: aplicações e recursos, serviços e contas de serviço. Um ponto importante: os controles 10, 12, 13 e 16 são somente auditoria, porque dependem do contexto da ATI-PE.

**Apoio.** Não ler os 16 um a um com pressa; agrupar.

## Slide 06 · Arquitetura modular, um ponto de entrada

**Fala.** A arquitetura tem um único ponto de entrada, o Main.ps1, onde se escolhe o modo, o perfil, os IDs e a pasta de saída. Ele usa quatro bibliotecas: Common, com o que é compartilhado; Safety, com as travas; Backup; e Reporting. E cada controle é um arquivo próprio, com o mesmo contrato: Get lê o estado, Set aplica, Test confere. Toda execução gera inventário antes e depois, em JSON, CSV, HTML e Markdown, e o backup com escopo.

## Slide 07 · A mudança é uma etapa, não o ponto de partida

**Fala.** O fluxo tem cinco etapas, e aplicar é só a quarta. Primeiro auditar o estado antes. Depois proteger: snapshot da VM e backup local. Depois autorizar: o arquivo de aprovação diz qual máquina, quais IDs e até quando. Só então aplicar, e cada mudança passa pelo ShouldProcess do PowerShell, que pede confirmação. Por fim verificar o estado depois. Audit é o padrão, e o parâmetro WhatIf simula tudo sem mudar nada. E vale reforçar: backup local não é snapshot. O rollback só cobre a configuração que o script sabe restaurar.

**Apoio.** Se houver tempo, mostrar `.\Main.ps1 -Mode Apply -WhatIf` rodando.

## Slide 08 · 01 a 06: autenticação e limitação de tentativas

**Fala.** Aqui está o código real do controle 01, linha 31. Ele lê o valor do perfil, pergunta pelo ShouldProcess e só então chama o secedit, alterando apenas a chave MinimumPasswordLength. O conceito de sistema operacional é que a base de políticas persiste as regras de autenticação. O risco reduzido é senha fraca e tentativa repetida, mas o bloqueio tem um preço: alguém pode bloquear contas de propósito. E uma observação honesta: o checklist pede complexidade e rotação de 90 dias, e recomendações modernas como o NIST pedem revisão disso.

## Slide 09 · 07 a 10: identidade, tokens e fronteiras de confiança

**Fala.** No controle 07, linha 79, renomeamos a conta Administrador pelo SID, e não pelo nome. O SID é o que identifica a conta de verdade; grupos e tokens determinam os privilégios. Renomear tira o alvo óbvio, mas é uma medida complementar: o SID continua terminando em 500. O 08 desabilita o Convidado, o 09 coloca o UAC na área de trabalho segura, e o 10, logon de rede de contas locais, fica só em auditoria, porque negar isso pode cortar compartilhamentos que a ATI-PE usa.

## Slide 10 · 11: auditoria transforma eventos em rastreabilidade

**Fala.** No controle 11 a gente consulta a subcategoria de logon pelo GUID, e não pelo nome, porque o nome muda com o idioma do Windows. Habilitamos sucesso e falha só nesse escopo. Com isso o serviço de eventos registra o evento 4624 para logon com sucesso e 4625 para falha, e o 4740 quando uma conta é bloqueada. Sem isso, as tentativas de ataque não deixam rastro.

## Slide 11 · 12: firewall e portas, observar antes de restringir

**Fala.** O 12 é somente auditoria. Ele lê os perfis efetivos do firewall, Domain, Private e Public, a ação padrão de entrada, e as portas em escuta com o processo dono de cada uma. Restringir portas sem a lista aprovada pela ATI-PE poderia derrubar a administração remota. Então o script aponta, por exemplo, uma porta 3389 de RDP aberta, e a decisão fica com quem opera.

## Slide 12 · 13 e 14: proteger a evidência e revisar privilégios

**Fala.** O 13 protege a evidência: lê a ACL da pasta de logs, o tamanho e o modo dos canais Security e System, e procura limpezas recentes, eventos 1102 e 104. Ele não troca permissões, porque isso afeta serviços. O 14 revisa contas, membros de Administradores e direitos sensíveis; a única coisa que ele aplica são as subcategorias de auditoria de contas e grupos, para que uma conta nova com privilégio vire evento.

## Slide 13 · 15 e 16: menos componentes, menos exposição

**Fala.** O 15 inventaria recursos opcionais e aplicações. Ele só desabilita um recurso, como o SMB1, que foi o protocolo explorado pelo WannaCry, se esse recurso estiver presente, habilitado e aprovado. O 16 lista serviços com contas fora das contas internas do Windows e caminhos de executável sem aspas, que são uma forma clássica de escalada de privilégio. Serviços e dependências ficam só em auditoria.

## Slide 15 · O que foi entregue e o que ainda falta validar

**Fala.** Entregamos relatório, matriz, apresentação e scripts modulares. A verificação local cobre estrutura, contratos estáticos e artefatos. No laboratório, a auditoria e a aplicação em VM ainda precisam ser feitas com a turma e a ATI-PE. E fazemos questão de dizer: não inventamos medições, prints nem eficácia. O que não foi executado está marcado como pendente.

**Apoio.** Se perguntarem: depois da apresentação, os testes com dublês e um ciclo completo em Windows foram adicionados à CI do repositório (ver README, seção Testes).

## Slide 16 · Próximos passos: validar com quem opera

**Fala.** Os próximos passos são três. Escopo: confirmar equipe, agenda e perfil com a professora e a ATI-PE. Laboratório: aprovar a VM, o snapshot, a conta de recuperação e testar ID por ID. Homologação: revisar evidências, riscos e exceções antes de qualquer implantação de verdade. E a mensagem final: hardening reduz a superfície de ataque, mas não garante invulnerabilidade. Obrigado.

**Apoio.** Abrir para perguntas. Referências do slide: checklist de Gabriel Cortez e Rodrigo Campos; Microsoft Learn (auditpol, secedit); NIST SP 800-63B-4; gov.br/cisc.
