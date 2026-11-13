# Plano de testes e evidências

O projeto é testado em quatro níveis. Os três primeiros não alteram nenhuma máquina; o quarto altera e por isso roda só em ambiente descartável.

## 1. Estrutura (Python)

`python3 tests/test_static.py -v` confere, sem PowerShell:

- exatamente 16 arquivos de controle, com os nomes do catálogo;
- cada controle define `Get-HWControlNN` e `Test-HWControlNN`; os aplicáveis também `Set-` e `Restore-`, sempre com `SupportsShouldProcess`;
- os controles 10, 12, 13 e 16 não chamam nenhum comando de alteração (`Set-*`, `Disable-*`, `secedit /configure`, `auditpol /set` etc.);
- os trechos de código dos slides 08 a 13 estão nas linhas citadas (`01-SenhaMinima.ps1:31`, `07-RenomearAdministrador.ps1:79`, `11-AuditoriaLogon.ps1:68`, `12-FirewallEPortas.ps1:6`, `13-ProtecaoLogs.ps1:8`, `15-AplicacoesERecursos.ps1:81`);
- todos os scripts em UTF-8 com BOM (sem BOM, o Windows PowerShell 5.1 lê "Política" errado);
- o perfil de exemplo não é mais fraco que o checklist e a aprovação de exemplo não autoriza nada;
- todos os links e imagens do README existem.

## 2. Estático (PowerShell)

`.\tests\Test-Static.ps1` analisa a sintaxe de todos os scripts e roda o PSScriptAnalyzer com [PSScriptAnalyzerSettings.psd1](../PSScriptAnalyzerSettings.psd1). As regras `PSUseCompatibleSyntax`, `PSUseCompatibleCommands` e `PSUseCompatibleTypes` comparam o código com o perfil do **Windows PowerShell 5.1 no Windows 10/Server 2019**, então um cmdlet ou parâmetro que não exista no Windows é apontado mesmo quando a análise roda em Linux.

## 3. Contratos com dublês (Pester 5)

`.\tests\Test-Contracts.ps1` roda 92 testes em `tests/pester/`:

| Arquivo | O que cobre |
|---------|-------------|
| `Bibliotecas.Tests.ps1` | Catálogo; validação do perfil; leitura do `.inf` do secedit (UTF-16) e do CSV do auditpol em inglês e português; aprovação (máquina, validade, snapshot, laboratório, conta de recuperação, VM); plataforma (build, domínio, controlador de domínio, PowerShell 7); mutex contra execução simultânea; backup (hash, outra máquina, `-WhatIf`); relatórios e códigos de saída |
| `Controles.Tests.ps1` | Para cada controle: Get com dados de exemplo, Set alterando somente o escopo, `-WhatIf` sem chamada real, Restore com os valores salvos; 07 renomeia pelo SID e recusa nome vazio ou em uso; 15 só desabilita recurso aprovado |
| `Main.Tests.ps1` | `-WhatIf/-Confirm` disponíveis, modo padrão Audit, ID inválido recusado, bloqueio com código 3 fora do Windows e com perfil inválido |

Os cmdlets do Windows (`Get-LocalUser`, `Get-NetFirewallProfile`, `Get-WindowsOptionalFeature` etc.) são simulados; em Linux eles são criados como funções vazias só para poderem ser simulados.

## 4. Ciclo real no Windows

`.\tests\Invoke-CicloLaboratorio.ps1 -SaidaDir C:\evidencias -ConfirmoVmDescartavel [-PrepararNaoConformidades]`

1. gera perfil e aprovação temporários para a máquina atual;
2. audita os 16 controles;
3. simula a aplicação (`-WhatIf`) e confere que nada mudou;
4. aplica todos os controles aplicáveis e confere que nenhum deu erro e que todos ficaram "Conforme" ou "Revisar";
5. restaura com o backup gravado pela aplicação;
6. audita de novo e confere, controle a controle, que os valores voltaram exatamente ao estado inicial.

A CI do GitHub roda esse ciclo num `windows-latest` (VM descartável) em todo push, com `-PrepararNaoConformidades` para que a conta Convidado e o TelnetClient também sejam aplicados e restaurados. Os relatórios ficam no artefato `evidencias-windows` da execução.

## Roteiro na VM do laboratório

Pré-requisitos: VM Windows 10/11 Pro ou Windows Server, fora de domínio, snapshot tirado, uma segunda conta administradora testada.

| Passo | Comando | Evidência a guardar |
|-------|---------|---------------------|
| Auditoria inicial | `.\Main.ps1` | `relatorio.html` e `estado-antes.json` |
| Simulação | `.\Main.ps1 -Mode Apply -WhatIf` | Saída "What if" no console |
| Aplicação por grupo | `.\Main.ps1 -Mode Apply -ControlIds '01','02','03','04','05','06'` (depois 07-09, 11, 14, 15) | `relatorio.html` com antes/depois, pasta `backup` |
| 01-06 | `net accounts` e `secpol.msc` → Diretivas de Conta | Print mostrando 12 / habilitada / 5 / 90 / 5 / 15 |
| 05-06 | Errar a senha de uma conta de teste 5 vezes | Conta bloqueada; evento 4740 e 4625 no Visualizador de Eventos |
| 07-08 | `Get-LocalUser \| Select Name, SID, Enabled` | SID −500 com nome novo; −501 desabilitada |
| 09 | Abrir um programa como administrador | Prompt do UAC na área de trabalho escurecida |
| 11 / 14 | `auditpol /get /category:*` | Logon e Gerenciamento de conta/grupo com Êxito e Falha |
| 14 | Criar e apagar um usuário de teste | Eventos 4720 e 4726 |
| 15 | `Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol` | Estado Disabled (se aprovado) |
| Rollback | `.\Main.ps1 -Mode Rollback -BackupPath .\saida\<pasta>\backup` | Relatório com "Restaurado" e auditoria final igual à inicial |
| Encerramento | Voltar o snapshot | — |

Nenhuma medição, print ou taxa de eficácia deve ser inventada: o que não foi executado fica marcado como pendente.
