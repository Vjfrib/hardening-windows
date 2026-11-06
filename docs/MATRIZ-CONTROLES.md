# Matriz de controles de hardening

A numeração segue os 16 itens da tabela final do checklist de Gabriel Cortez e Rodrigo Campos. Os valores descrevem o perfil acadêmico. A conformidade e a eficácia operacional precisam ser verificadas na VM alvo.

| ID | Alvo acadêmico | Auditoria e aplicação |
|---|---|---|
| 01 | Comprimento mínimo de senha de 12 caracteres | Compara a política de senha e preserva valores que já atinjam o alvo. |
| 02 | Complexidade habilitada | Lê e aplica somente a diretiva de complexidade. |
| 03 | Histórico de pelo menos cinco senhas | Compara a política de histórico e preserva valores que já atinjam o alvo. |
| 04 | Validade positiva de até 90 dias | Verifica a idade mínima observada antes de reduzir o máximo. |
| 05 | Bloqueio após cinco falhas | Revisa limites de uma a quatro falhas sem afrouxá-los automaticamente. Aplica após conferir a coerência da política de bloqueio. |
| 06 | Duração de pelo menos 15 minutos e zeragem positiva até o limite da duração | Trata duração e zeragem em conjunto. A duração indefinida exige revisão. Precede o ID 05 no modo Apply. |
| 07 | Renomear a conta interna Administrador | Identifica o SID terminado em `-500`. A renomeação exige nome aprovado e outro acesso administrativo local habilitado e confirmado. |
| 08 | Desabilitar a conta interna Convidado | Identifica o SID terminado em `-501` e desabilita a conta apenas se estiver habilitada. |
| 09 | UAC elevado com área de trabalho segura | Verifica `EnableLUA=1`, `ConsentPromptBehaviorAdmin=2` e `PromptOnSecureDesktop=1`. Aplica somente as diferenças com estado anterior conhecido. |
| 10 | Revisar logon de rede e logon remoto interativo de contas locais | Somente auditoria. Os direitos e os fluxos dependem do cenário autorizado. |
| 11 | Sucesso e falha na auditoria de logon | Identifica a subcategoria Logon por GUID e aplica somente essa política. |
| 12 | Firewall ativo nos perfis Domain, Private e Public, com entrada bloqueada por padrão e exceções revisadas | Somente auditoria. Inventaria a política efetiva e as portas em escuta. Valide a alcançabilidade em teste separado de conectividade. |
| 13 | Preservar os logs e revisar os acessos | Somente auditoria. Coleta ACLs, descritores ou direitos relevantes à revisão da administração e da proteção dos logs. |
| 14 | Revisar grupos e direitos privilegiados | Inventaria membros e direitos. A aplicação altera apenas a auditoria de gerenciamento de contas e grupos. A revisão dos acessos continua manual. |
| 15 | Revisar aplicações e recursos opcionais | A desabilitação se limita a recursos opcionais presentes e aprovados tanto no perfil quanto na autorização. O programa preserva o payload e evita reinício automático. |
| 16 | Revisar serviços e suas contas | Somente auditoria. Inventaria o serviço e suas dependências para que o responsável avalie uso e privilégio. |

A rotação periódica e a complexidade de senha representam parâmetros do checklist. A adoção depende de revisão junto aos administradores responsáveis.
