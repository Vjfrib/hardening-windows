# Hardening Windows: contas e políticas de acesso

Script em PowerShell que verifica e aplica os 16 itens do checklist **"Hardening Windows - Contas e Políticas de Acesso"** (Gabriel Cortez e Rodrigo Campos), do projeto de Sistemas Operacionais da Poli/UPE com a ATI-PE.

## Uso rápido

No **Windows PowerShell como Administrador**, na pasta do repositório:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Get-ChildItem -Recurse | Unblock-File

.\Invoke-Hardening.ps1                 # só verifica, não muda nada
.\Invoke-Hardening.ps1 -Modo Aplicar   # faz backup, aplica e verifica de novo
```

O relatório (HTML e CSV, com o antes e depois de cada item) fica em `relatorios\`. Teste numa VM antes de aplicar numa máquina de verdade.

## Estrutura

| Caminho | Conteúdo |
| --- | --- |
| `Invoke-Hardening.ps1` | Ponto de entrada: modos Auditar e Aplicar, backup e relatório. |
| `config\hardening.config.psd1` | Valores do checklist e listas que dependem da ATI-PE. |
| `itens\` | Um arquivo por item do checklist (01 a 16), cada um com a verificação e a aplicação. |
| `src\` | Funções de apoio (secedit, auditpol, registro, relatório). |
| `docs\documentacao.md` | Documentação completa: como executar, o que cada item faz, como desfazer. |
| `.github\workflows\validar.yml` | Validação automática numa máquina Windows descartável do GitHub. |

Leia [docs/documentacao.md](docs/documentacao.md) antes de aplicar.
