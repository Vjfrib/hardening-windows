# Hardening Windows

Automação acadêmica de Sistemas Operacionais da UPE/POLI, baseada no checklist de Gabriel Cortez e Rodrigo Campos. O perfil cobre 16 controles de segurança e depende de homologação da ATI-PE antes de qualquer implantação.

## Auditoria e demonstração

O alvo do laboratório é uma VM Windows 11 Pro x64 em grupo de trabalho, com Windows PowerShell 5.1 x64 e console do hipervisor disponível. Outras edições e cenários gerenciados precisam de validação própria. O modo padrão, `Audit`, coleta e compara a configuração. `Verify` faz uma nova coleta.

```powershell
.\Main.ps1
.\Main.ps1 -Mode Audit -ControlIds '01','08','09','11'
.\Main.ps1 -Mode Verify -ControlIds '01','08','09','11'
```

Cada coleta cria um subdiretório em `output/`, com um identificador único e timestamp UTC. Use o caminho da coleta para reabrir o relatório a partir de `results.json`:

```powershell
.\Main.ps1 -Mode Report -OutputDirectory '.\output\ID-DA-COLETA'
```

Os formatos JSON, CSV, HTML e Markdown servem à revisão da mesma coleta. Guarde os resultados com acesso restrito, pois registram configurações de segurança da máquina. A opção `-Demo` mostra a estrutura dos resultados com dados marcados como **SIMULAÇÃO**.

```powershell
.\Main.ps1 -Demo
```

Os códigos de saída são `0` quando não há pendências, `1` para falha técnica ou de verificação, `2` para desvio de conformidade e `3` quando há simulação, bloqueio ou revisão pendente. Consulte o estado de cada controle no relatório quando houver resultados diferentes na mesma execução.

## Mudanças em laboratório

Antes de aplicar, crie um snapshot externo no hipervisor e revise a configuração observada. Para planejar a execução sem rodar os setters:

```powershell
.\Main.ps1 -Mode Apply -ControlIds '01' -WhatIf
```

As aprovações incluídas começam desativadas. Para um ensaio autorizado, use cópias locais revisadas dos modelos em `scripts/config/`. No arquivo de aprovação, defina `EnableMutations` e `ConfirmedLab` como verdadeiros após preparar a VM. Preencha `SnapshotId`, `Approver` e `Reason`. Em `Controls`, habilite `Enabled` e informe o `Ticket` para cada ID autorizado. Execute pelo console da VM em uma sessão elevada:

```powershell
.\Main.ps1 -Mode Apply -ControlIds '01' -ConfigPath '.\perfil.local.json' -ApprovalPath '.\aprovacoes.local.json' -ConfirmApply
```

Os IDs **10, 12, 13 e 16** são somente auditoria. O ID 14 configura apenas as subcategorias de auditoria de contas e grupos. O ID 15 pode desabilitar apenas recursos opcionais aprovados no perfil e em `ApprovedFeatures` na autorização do ID. O ID 07 exige um nome aprovado e `RecoveryAccessConfirmed` após o teste de outro acesso administrativo pelo console.

## Recuperação

O modo `Rollback` usa o backup de um único controle suportado (01–09, 11 ou 14), com `RollbackEnabled` na autorização do ID. O backup precisa ter sido concluído na mesma VM, e a configuração atual precisa corresponder ao estado pós-aplicação registrado. O retorno integral da VM é feito pelo hipervisor. Avalie esse procedimento se a aplicação tiver falhado parcialmente, se o controle exigir recuperação manual ou se outra mudança tiver alterado a configuração.

```powershell
.\Main.ps1 -Mode Rollback -ControlIds '01' -BackupPath '.\output\ID-DA-COLETA\backups\01.json' -ConfigPath '.\perfil.local.json' -ApprovalPath '.\aprovacoes.local.json' -ConfirmApply
```

## Organização

- `Main.ps1` coordena a seleção de controles, modos, aprovação e saída.
- `scripts/controles/` contém um script por ID, com as funções `Get-HWxxState`, `Set-HWxxState` e `Test-HWxxState`.
- `scripts/lib/` reúne os módulos Common, Safety, Backup, Reporting e Rollback.
- [Matriz de controles](docs/MATRIZ-CONTROLES.md) e [Plano de testes em VM](docs/PLANO-DE-TESTES.md) detalham os alvos e a validação.
- `tests/` contém verificações do pacote. A comprovação de cada efeito no Windows depende de ensaio autorizado em VM.

## Conceitos de Sistemas Operacionais

| Controles | Conceitos |
|---|---|
| 01–06 | Autenticação, persistência de políticas de segurança e disponibilidade |
| 07–08 | SID, identidade local e menor privilégio |
| 09–10 | Tokens, elevação de privilégios e fronteiras de confiança |
| 11, 13 e 14 | Auditoria, logs de eventos, ACLs e gerenciamento de identidades |
| 12 | Pilha de rede, sockets e firewall |
| 15–16 | Processos, serviços, contas de serviço e dependências |

