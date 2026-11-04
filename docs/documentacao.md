# Automação do checklist de hardening do Windows

Disciplina de Sistemas Operacionais, Escola Politécnica de Pernambuco (UPE), professora Tarciana Dias, em parceria com a ATI-PE.

Este documento descreve o script que automatiza o checklist **"Hardening Windows - Contas e Políticas de Acesso"**, feito por Gabriel Cortez e Rodrigo Campos. Ele é a segunda das três frentes do projeto:

1. **Checklist de assertivas de hardening:** Rodrigo Campos e Gabriel Cortez.
2. **Automação das assertivas por script:** este repositório.
3. **Relatório dos tipos de ataque impedidos:** Caio Tenório e Tiago Gaspar, a partir deste material.

O script cobre os 16 itens da tabela do checklist. Para cada item ele segue o processo de validação da seção 4 do checklist: captura o estado inicial, aplica a alteração e captura o estado final. O relatório que ele gera serve de evidência do antes e depois.

## 1. Como executar

**Requisitos:** Windows 10, Windows 11 ou Windows Server 2016 em diante, Windows PowerShell 5.1 (já vem no Windows) e uma conta de Administrador. Teste sempre numa VM antes de usar numa máquina de produção.

1. Baixe o repositório e abra o **Windows PowerShell como Administrador** na pasta dele.
2. Libere a execução só nesta janela e desbloqueie os arquivos baixados:

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   Get-ChildItem -Recurse | Unblock-File
   ```

3. Rode a auditoria. Ela só lê a configuração e não muda nada:

   ```powershell
   .\Invoke-Hardening.ps1
   ```

4. Revise `config\hardening.config.psd1` (seção 3 deste documento), principalmente o nome novo do Administrador (item 7) e as listas da ATI-PE (itens 12, 15 e 16).
5. Aplique o checklist. O script pede confirmação e salva um backup antes:

   ```powershell
   .\Invoke-Hardening.ps1 -Modo Aplicar
   ```

6. Reinicie a máquina. As mudanças de UAC (item 9) e de recursos do Windows (item 15) só valem depois de reiniciar.

Para rodar só alguns itens, use `-Itens`. Por exemplo, só a política de senha:

```powershell
.\Invoke-Hardening.ps1 -Modo Aplicar -Itens 1,2,3,4
```

| Parâmetro | O que faz |
| --- | --- |
| `-Modo Auditar` | Padrão. Só verifica e gera o relatório. |
| `-Modo Aplicar` | Faz backup, aplica os itens fora do checklist e verifica de novo. |
| `-Itens 1,5,12` | Escolhe os itens (1 a 16). Padrão: todos. |
| `-Configuracao arquivo.psd1` | Usa outro arquivo de configuração. |
| `-Forcar` | No modo Aplicar, não pede confirmação. |
| `-PassThru` | Devolve os resultados como objetos do PowerShell. |

## 2. O que o script gera

Cada execução cria uma pasta `relatorios\<data>-<modo>\` com:

| Arquivo | Conteúdo |
| --- | --- |
| `relatorio.html` | Tabela com os 16 itens: esperado, antes, depois, ação e detalhes. Pronto para imprimir ou anexar como evidência. |
| `resultado.csv` | Os mesmos dados, para abrir no Excel. |
| `evidencias\` | Listas completas usadas na verificação, separadas em `antes-` e `depois-`: portas em escuta, permissões da pasta de logs, membros de Administradores, aplicações instaladas, serviços. |
| `backup\` | Só no modo Aplicar: cópia da configuração antes da mudança (seção 5). |
| `execucao.log` | Tudo o que apareceu na tela. |

Cada item recebe um destes resultados:

| Resultado | Significado |
| --- | --- |
| **OK** | Está como o checklist pede. |
| **FALHA** | Está fora do checklist. O modo Aplicar corrige. |
| **REVISAR** | A parte automática está certa, mas falta uma decisão da ATI-PE (por exemplo, a lista de portas permitidas). O campo Detalhes diz o quê. |
| **ERRO** | O script não conseguiu verificar ou aplicar. O campo Detalhes traz a mensagem. |

## 3. Configuração

Os valores do checklist ficam em `config\hardening.config.psd1`. O arquivo já vem com os valores recomendados pelo checklist.

| Chave | Item | Padrão | Observação |
| --- | --- | --- | --- |
| `Senha.TamanhoMinimo` | 1 | 12 | O CIS sugere 14. |
| `Senha.Complexidade` | 2 | `$true` | |
| `Senha.Historico` | 3 | 5 | O CIS sugere 24. |
| `Senha.DuracaoMaximaDias` | 4 | 90 | |
| `Bloqueio.Tentativas` | 5 | 5 | |
| `Bloqueio.DuracaoMinutos` | 6 | 15 | |
| `Bloqueio.ZerarContadorMinutos` | 6 | 15 | Precisa ser menor ou igual à duração. |
| `NovoNomeAdministrador` | 7 | vazio | **Defina com a ATI-PE.** Vazio = só verifica. |
| `ContasNegadasNaRede` | 10 | Conta local e Convidados | Veja o cuidado do item 10. |
| `TamanhoMinimoLogSegurancaKB` | 11 | 196608 (192 MB) | |
| `PortasPermitidas` | 12 | vazio | **Lista da ATI-PE.** Vazio = só lista as portas. |
| `RecursosDesabilitar` | 15 | SMB 1.0, Telnet, TFTP | |
| `AplicacoesAprovadas` | 15 | vazio | **Lista da ATI-PE.** Aceita curinga, como `'Microsoft Edge*'`. |
| `ServicosDesabilitar` | 16 | RemoteRegistry, SSDPSRV, upnphost | Confirme com a ATI-PE. |
| `ContasDeServico` | 16 | vazio | Contas de serviço que não devem fazer logon interativo. |
| `DesabilitarContasSemUso` | 16 | `$false` | `$true` = o modo Aplicar desabilita contas locais sem logon há mais de `DiasSemUsoConta` dias. |

## 4. Como cada item é tratado

A tabela resume. As subseções abaixo seguem as seções 3.1 a 3.6 do checklist e detalham o que o script verifica, o que aplica e os cuidados de cada item. O risco que cada item reduz está justificado no checklist do Rodrigo e do Gabriel, seção 3.

| # | Item | Automação | Ferramenta usada |
| --- | --- | --- | --- |
| 1 | Tamanho mínimo de senha | Completa | `secedit` |
| 2 | Complexidade de senha | Completa | `secedit` |
| 3 | Histórico de senhas | Completa | `secedit` |
| 4 | Duração máxima da senha | Completa | `secedit` |
| 5 | Limite de tentativas de login | Completa | `secedit` |
| 6 | Duração do bloqueio de conta | Completa | `secedit` |
| 7 | Renomear o Administrador padrão | Completa (com o nome definido) | `Rename-LocalUser` |
| 8 | Desabilitar a conta Convidado | Completa | `Disable-LocalUser` |
| 9 | UAC com nível elevado | Completa | Registro |
| 10 | Restringir contas locais em rede | Completa | `secedit` e registro |
| 11 | Auditoria de logon | Completa | `auditpol` e `wevtutil` |
| 12 | Controlar as portas de rede | Parcial | `Set-NetFirewallProfile`, `Get-NetTCPConnection` |
| 13 | Proteger os arquivos de log | Parcial | `icacls`, `secedit` |
| 14 | Proteger a criação de usuários e grupos | Completa | `secedit`, `auditpol` |
| 15 | Remover aplicações e recursos | Parcial | `Disable-WindowsOptionalFeature`, inventário do registro |
| 16 | Revisar contas de serviço | Parcial | `Set-Service`, `secedit`, `Disable-LocalUser` |

"Parcial" quer dizer que o script aplica a parte técnica e lista o resto para revisão, porque depende de uma lista que só a ATI-PE pode dar. O script nunca fecha portas, desinstala programas ou desabilita contas sem essa lista.

O script identifica contas e grupos pelo SID (por exemplo, `S-1-5-32-544` para Administradores) e as subcategorias de auditoria pelo GUID. Assim ele funciona igual no Windows em português e em inglês, em que os nomes mudam.

### 4.1 Política de senha (itens 1 a 4)

**Verifica:** exporta a diretiva de segurança local com `secedit /export` e lê a seção `[System Access]`: `MinimumPasswordLength`, `PasswordComplexity`, `PasswordHistorySize` e `MaximumPasswordAge`.

**Aplica:** gera um modelo `.inf` só com os valores do checklist e aplica com `secedit /configure`, equivalente a mudar em `secpol.msc` > Diretivas de Conta > Diretiva de Senha.

**Cuidados:** as novas regras valem na próxima troca de senha; senhas atuais não são invalidadas. No item 4, "a senha nunca expira" conta como fora do checklist.

**Evidência:** valores antes e depois no relatório. O teste prático do checklist (tentar definir uma senha fraca e reutilizar uma recente) continua manual.

### 4.2 Bloqueio de conta (itens 5 e 6)

**Verifica:** `LockoutBadCount` (tentativas), `LockoutDuration` (duração) e `ResetLockoutCount` (tempo para zerar o contador) na mesma exportação do `secedit`.

**Aplica:** bloqueio após 5 tentativas, por 15 minutos, com o contador zerado em 15 minutos. O Windows só guarda a duração quando o limite de tentativas está ligado; por isso o item 6 liga o item 5 junto se ele estiver desligado.

**Cuidados:** defina quem desbloqueia contas e em quanto tempo, como pede o checklist.

**Evidência:** valores no relatório. O teste prático (errar a senha 5 vezes e ver o evento 4740 no log) continua manual.

### 4.3 Contas privilegiadas (itens 7 e 8)

**Item 7, verifica:** acha a conta pelo SID terminado em 500 e confere se o nome não está em `NomesObviosAdministrador`.
**Item 7, aplica:** `Rename-LocalUser` com o nome de `NovoNomeAdministrador`. Se o nome não estiver definido, o item aparece como "Não aplicado" e nada muda.

**Item 8, verifica e aplica:** acha a conta Convidado pelo SID terminado em 501 e a desabilita com `Disable-LocalUser`.

**Cuidados:** renomear não muda o SID, então é uma medida complementar (como o checklist observa). Atualize scripts e documentação interna que usem o nome antigo.

### 4.4 Controle de privilégios e acesso (itens 9 e 10)

**Item 9, verifica e aplica** em `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:

| Valor | Esperado | Significado |
| --- | --- | --- |
| `EnableLUA` | 1 | Modo de aprovação do administrador ligado |
| `FilterAdministratorToken` | 1 | Modo de aprovação também para o Administrador padrão |
| `ConsentPromptBehaviorAdmin` | 2 (ou 1) | Pedir consentimento (ou credenciais) na área de trabalho segura |
| `PromptOnSecureDesktop` | 1 | Usar a área de trabalho segura |

**Cuidados do item 9:** `EnableLUA` só muda depois de reiniciar.

**Item 10, verifica e aplica:**

- Inclui as contas de `ContasNegadasNaRede` no direito "Negar acesso a este computador pela rede" (`SeDenyNetworkLogonRight`), sem tirar quem já estava lá.
- Deixa o "Modelo de compartilhamento e segurança para contas locais" como Clássico (`ForceGuest = 0`).
- Mantém `LocalAccountTokenFilterPolicy = 0`, que aplica as restrições do UAC a administradores locais que entram pela rede.

**Cuidados do item 10:** com `*S-1-5-113` (todas as contas locais), compartilhamentos e administração remota com conta local param de funcionar, inclusive **RDP com conta local quando o NLA está ligado**. Se a VM só é acessada por RDP com conta local, aplique pelo console da VM ou troque para `*S-1-5-114` (só contas locais administradoras). O checklist pede testar antes da aplicação geral.

### 4.5 Auditoria (item 11)

**Verifica:** lê a auditoria pelo backup do `auditpol` (que traz números e GUIDs, não textos traduzidos) e o tamanho máximo do log de Segurança.

**Aplica:**

- Logon: sucesso e falha (eventos 4624 e 4625).
- Bloqueio de Conta: falha.
- Liga "Forçar configurações de subcategoria da diretiva de auditoria" (`SCENoApplyLegacyAuditPolicy = 1`) para as subcategorias valerem.
- Aumenta o log de Segurança para no mínimo 192 MB, porque a auditoria aumenta o volume de eventos.

**Cuidados:** o evento 4740 (conta bloqueada), citado no checklist, vem da auditoria de Gerenciamento de Contas de Usuário, ligada pelo item 14.

### 4.6 Lacunas apontadas pela ATI-PE (itens 12 a 16)

#### Item 12: controlar as portas de rede abertas

**Verifica:** os três perfis do Firewall do Windows (Domínio, Privado e Público) e as portas TCP em escuta, com o processo dono. Ignora o endereço de loopback e, por padrão, as portas dinâmicas do RPC (49152 a 65535).

**Aplica:** firewall ligado nos três perfis, entrada bloqueada por padrão e saída liberada (`Set-NetFirewallProfile`).

**Revisão:** se `PortasPermitidas` estiver vazia, o item fica em REVISAR com a lista das portas abertas. Com a lista definida, ele aponta as portas fora dela. O script não cria nem remove regras de porta: fechar 445 (SMB) ou 3389 (RDP) sem saber quem usa pode derrubar serviços. Liberar essas portas só para as origens necessárias continua sendo feito em `wf.msc` ou por GPO.

**Evidência:** `evidencias\antes-item12-portas-em-escuta.csv` e `depois-...`. A varredura de portas a partir de outra máquina, sugerida no checklist, continua manual.

#### Item 13: proteger os arquivos de log

**Verifica:**

1. As permissões de `C:\Windows\System32\winevt\Logs`. Só SYSTEM, Administradores, o serviço de log de eventos e o TrustedInstaller podem escrever ou apagar.
2. O direito "Gerenciar auditoria e log de segurança" (`SeSecurityPrivilege`), que deve ser só de Administradores.
3. Se existe encaminhamento de eventos para um servidor central.

**Aplica:** remove com `icacls /remove:g` as permissões de escrita de outras contas (só as permissões explícitas, não herdadas) e deixa `SeSecurityPrivilege` só para Administradores.

**Revisão:** o encaminhamento para o servidor central e o alerta sobre os eventos 1102 (log de Segurança limpo) e 104 (log de Sistema limpo) dependem da infraestrutura da ATI-PE. Enquanto não houver coletor configurado, o item fica em REVISAR.

**Evidência:** `evidencias\antes-item13-permissoes-winevt-logs.txt`. O teste prático (um usuário comum tentar limpar o log e ser recusado) continua manual.

#### Item 14: proteger a criação de usuários e grupos

**Verifica e aplica:**

1. Deixa só Administradores nos direitos "Assumir a propriedade de arquivos ou outros objetos", "Fazer backup de arquivos e diretórios", "Restaurar arquivos e diretórios" e "Depurar programas".
2. Liga a auditoria de sucesso e falha de Gerenciamento de Contas de Usuário (eventos 4720, 4740) e de Grupos de Segurança (evento 4732).

**Cuidados:** tirar o grupo Operadores de Cópia dos direitos de backup e restauração pode afetar programas de backup que usam esse grupo.

**Evidência:** `evidencias\antes-item14-membros-administradores.txt`. Para mostrar o evento 4720 no log, crie uma conta de teste depois de aplicar.

#### Item 15: remover aplicações e recursos desnecessários

**Verifica:** o estado dos recursos de `RecursosDesabilitar` (`Get-WindowsOptionalFeature`) e o inventário das aplicações instaladas (lido do registro, mais rápido e confiável que `Get-Package`).

**Aplica:** desativa os recursos ligados com `Disable-WindowsOptionalFeature -NoRestart`. Recursos que não existem na edição do Windows contam como OK.

**Revisão:** o script compara o inventário com `AplicacoesAprovadas`, mas não desinstala nada, porque o checklist pede confirmar com os usuários antes. Como evolução, a lista aprovada pode ser imposta com AppLocker.

**Evidência:** `evidencias\antes-item15-aplicacoes-instaladas.csv` e `antes-item15-recursos.txt`, e as versões `depois-`.

#### Item 16: revisar contas de serviço sem uso

**Verifica:**

1. Se os serviços de `ServicosDesabilitar` estão desabilitados e parados.
2. Quais serviços rodam com contas que não são as do próprio Windows (LocalSystem, LocalService, NetworkService e contas virtuais `NT SERVICE\...`).
3. Se as contas de `ContasDeServico` estão em "Negar logon localmente" e "Negar logon pelos Serviços de Área de Trabalho Remota".
4. Contas locais habilitadas sem logon há mais de `DiasSemUsoConta` dias.

**Aplica:** desabilita e para os serviços da lista, nega logon interativo às contas de serviço e, só se `DesabilitarContasSemUso = $true`, desabilita as contas locais sem uso.

**Cuidados:** o checklist sugere desativar primeiro e remover só depois de um período de observação. O script nunca apaga contas nem serviços.

**Evidência:** `evidencias\antes-item16-servicos.csv` e `depois-item16-servicos.csv`.

## 5. Como desfazer

O modo Aplicar salva em `relatorios\<data>-Aplicar\backup\` a configuração anterior. Para voltar, num PowerShell como Administrador, dentro dessa pasta:

| O que voltar | Comando |
| --- | --- |
| Senha, bloqueio e direitos de usuário (itens 1 a 6, 10, 13, 14, 16) | `secedit /configure /db "$env:TEMP\volta.sdb" /cfg .\diretiva-seguranca.inf /areas SECURITYPOLICY USER_RIGHTS` |
| Auditoria (itens 11 e 14) | `auditpol /restore /file:.\auditoria.csv` |
| Firewall (item 12) | `netsh advfirewall import .\firewall.wfw` |
| UAC (itens 9 e 10) | `reg import .\uac.reg` |
| LSA (itens 10 e 11) | `reg import .\lsa.reg` |
| Permissões da pasta de logs (item 13) | `icacls C:\Windows\System32\winevt /restore .\permissoes-winevt-logs.txt` |
| Nome do Administrador (item 7) | `Rename-LocalUser -SID <SID que termina em 500> -NewName Administrador` |
| Convidado (item 8) | `Enable-LocalUser -SID <SID que termina em 501>` |
| Recursos do Windows (item 15) | `Enable-WindowsOptionalFeature -Online -FeatureName <nome>` |
| Serviços (item 16) | `Set-Service -Name <nome> -StartupType <tipo em servicos.csv>` |

## 6. Limitações

- Numa máquina em domínio, as GPOs do domínio têm prioridade sobre a diretiva local. Se uma GPO define outro valor, o item volta a FALHA na próxima atualização de diretiva; nesse caso o ajuste tem de ser feito na GPO.
- A validação automática roda no Windows Server do GitHub Actions (veja `.github/workflows/validar.yml`). Ela confirma que os 16 itens são verificados e aplicados sem erro, mas não substitui o teste numa VM igual à imagem padrão da ATI-PE.
- Os testes práticos do checklist (senha fraca recusada, conta bloqueada após 5 erros, usuário comum sem permissão de limpar o log, varredura de portas de outra máquina) continuam manuais.
