#Requires -Version 5.1
<#
.SYNOPSIS
    Verifica e aplica o checklist "Hardening Windows - Contas e Políticas de Acesso".

.DESCRIPTION
    Automatiza os 16 itens do checklist feito por Gabriel Cortez e Rodrigo Campos
    (Sistemas Operacionais, Poli/UPE, com a ATI-PE).

    Para cada item o script segue o processo da seção 4 do checklist:
      1. captura o estado inicial;
      2. aplica a alteração (só no modo Aplicar);
      3. captura o estado final.

    O resultado vai para relatorios\<data>-<modo>\ : relatorio.html, resultado.csv,
    evidencias\ (listas antes e depois), backup\ (modo Aplicar) e execucao.log.

.PARAMETER Modo
    Auditar (padrão): só lê o estado da máquina. Nada é alterado.
    Aplicar: faz backup, aplica os itens fora do checklist e verifica de novo.

.PARAMETER Itens
    Números dos itens do checklist a executar (1 a 16). Padrão: todos.

.PARAMETER Configuracao
    Arquivo .psd1 com os valores do checklist. Padrão: config\hardening.config.psd1.

.PARAMETER PastaRelatorios
    Onde salvar os relatórios. Padrão: relatorios\ ao lado do script.

.PARAMETER Forcar
    No modo Aplicar, não pede confirmação.

.PARAMETER PassThru
    Devolve os resultados como objetos (útil para outros scripts).

.EXAMPLE
    .\Invoke-Hardening.ps1
    Verifica os 16 itens e gera o relatório, sem alterar nada.

.EXAMPLE
    .\Invoke-Hardening.ps1 -Modo Aplicar -Itens 1,2,3,4
    Aplica só a política de senha (itens 1 a 4).
#>
[CmdletBinding()]
param(
    [ValidateSet('Auditar', 'Aplicar')]
    [string]$Modo = 'Auditar',

    [ValidateRange(1, 16)]
    [int[]]$Itens = (1..16),

    [string]$Configuracao = (Join-Path $PSScriptRoot 'config\hardening.config.psd1'),

    [string]$PastaRelatorios = (Join-Path $PSScriptRoot 'relatorios'),

    [switch]$Forcar,

    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'src\Comum.ps1')
. (Join-Path $PSScriptRoot 'src\Relatorio.ps1')

if (-not (Test-Administrador)) {
    throw 'Execute o PowerShell como Administrador (botão direito > Executar como administrador).'
}

$cfg = Import-PowerShellDataFile -Path $Configuracao

# Cada arquivo em itens\ devolve a definição de um item do checklist.
$definicoes = Get-ChildItem -Path (Join-Path $PSScriptRoot 'itens') -Filter '*.ps1' |
    Sort-Object Name |
    ForEach-Object { & $_.FullName }
$selecionados = @($definicoes | Where-Object { $Itens -contains $_.Id } | Sort-Object { $_.Id })

if ($Modo -eq 'Aplicar' -and -not $Forcar) {
    Write-Host ''
    Write-Host 'O modo Aplicar vai alterar configurações de segurança desta máquina.' -ForegroundColor Yellow
    Write-Host 'Teste antes numa VM. Um backup será salvo na pasta do relatório.' -ForegroundColor Yellow
    $resposta = Read-Host 'Digite S para continuar'
    if ($resposta -notin @('S', 's')) {
        Write-Host 'Cancelado. Nada foi alterado.'
        return
    }
}

$inicio = Get-Date
$pastaExecucao = Join-Path $PastaRelatorios ("{0}-{1}" -f $inicio.ToString('yyyyMMdd-HHmmss'), $Modo)
New-Item -ItemType Directory -Path $pastaExecucao -Force | Out-Null
$script:PastaEvidencias = Join-Path $pastaExecucao 'evidencias'
Start-Transcript -Path (Join-Path $pastaExecucao 'execucao.log') | Out-Null

try {
    Write-Host ''
    Write-Host ("Hardening Windows | modo {0} | {1} | {2} itens" -f $Modo, $env:COMPUTERNAME, $selecionados.Count) -ForegroundColor Cyan

    if ($Modo -eq 'Aplicar') {
        Write-Host 'Salvando backup da configuração atual...'
        Save-Backup -Pasta (Join-Path $pastaExecucao 'backup')
    }

    $cores = @{ OK = 'Green'; FALHA = 'Red'; REVISAR = 'Yellow'; ERRO = 'Magenta' }

    $resultados = foreach ($item in $selecionados) {
        try {
            $esperado = & $item.Esperado $cfg
        } catch {
            $esperado = "(erro na configuração: $($_.Exception.Message))"
        }

        $script:Fase = 'antes'
        try {
            $antes = & $item.Testar $cfg | Select-Object -Last 1
        } catch {
            $antes = New-Resultado -Status 'ERRO' -Detalhes $_.Exception.Message
        }

        $depois = $null
        $acao = '-'
        if ($Modo -eq 'Aplicar') {
            if ($antes.Status -eq 'OK') {
                $acao = 'Nada a fazer'
            } else {
                try {
                    & $item.Aplicar $cfg | Out-Null
                    $acao = 'Aplicado'
                } catch {
                    $acao = "Não aplicado: $($_.Exception.Message)"
                }
                Clear-CacheDiretiva
                $script:Fase = 'depois'
                try {
                    $depois = & $item.Testar $cfg | Select-Object -Last 1
                } catch {
                    $depois = New-Resultado -Status 'ERRO' -Detalhes $_.Exception.Message
                }
            }
        }

        $final = if ($depois) { $depois } else { $antes }
        $linha = '[{0,2}] {1,-45} {2}' -f $item.Id, $item.Nome, $final.Status
        if ($final.Valor) { $linha += " ($($final.Valor))" }
        Write-Host $linha -ForegroundColor $cores[$final.Status]
        if ($acao -like 'Não aplicado*') { Write-Host "     $acao" -ForegroundColor Magenta }

        [pscustomobject]@{
            Id           = $item.Id
            Secao        = $item.Secao
            Item         = $item.Nome
            Esperado     = $esperado
            StatusAntes  = $antes.Status
            ValorAntes   = $antes.Valor
            Acao         = $acao
            StatusDepois = if ($depois) { $depois.Status } else { '' }
            ValorDepois  = if ($depois) { $depois.Valor } else { '' }
            StatusFinal  = $final.Status
            Detalhes     = $final.Detalhes
        }
    }

    $relatorio = Export-Relatorio -Resultados $resultados -Pasta $pastaExecucao -Modo $Modo -Inicio $inicio

    Write-Host ''
    $resultados | Group-Object StatusFinal | Sort-Object Name | ForEach-Object {
        Write-Host ("{0}: {1}" -f $_.Name, $_.Count) -ForegroundColor $cores[$_.Name]
    }
    Write-Host "Relatório: $relatorio"
    if ($Modo -eq 'Aplicar') {
        Write-Host 'Reinicie a máquina para que todas as mudanças (UAC, recursos do Windows) tenham efeito.' -ForegroundColor Yellow
    }

    if ($PassThru) { $resultados }
} finally {
    Stop-Transcript | Out-Null
}
