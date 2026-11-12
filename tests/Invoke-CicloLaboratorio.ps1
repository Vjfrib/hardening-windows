#Requires -Version 5.1
<#
.SYNOPSIS
    Ciclo completo em uma VM descartável: auditar, aplicar, verificar, restaurar e auditar de novo.

.DESCRIPTION
    ALTERA A MÁQUINA. Use só em VM com snapshot ou em runner descartável (a CI do GitHub usa este
    script num windows-latest). Gera perfil e aprovação temporários para ESTA máquina e confere:
      1. a aplicação não tem erro e deixa os controles aprovados conformes (ou "Revisar");
      2. a restauração volta cada valor alterado ao estado da primeira auditoria.
    Com -PrepararNaoConformidades, antes do ciclo habilita a conta Convidado e o TelnetClient
    para que os controles 08 e 15 também tenham o que aplicar e restaurar.

.EXAMPLE
    .\tests\Invoke-CicloLaboratorio.ps1 -SaidaDir C:\evidencias -ConfirmoVmDescartavel
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SaidaDir,
    [switch]$ConfirmoVmDescartavel,
    [switch]$PrepararNaoConformidades,
    [string]$NovoNomeAdministrador = 'adm-lab-ci'
)

$ErrorActionPreference = 'Stop'
if (-not $ConfirmoVmDescartavel) { throw 'Este ciclo altera a máquina. Rode só em VM descartável e passe -ConfirmoVmDescartavel.' }
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Somente Windows.' }

$root = Resolve-Path (Join-Path $PSScriptRoot '..')
$main = Join-Path $root 'Main.ps1'
Import-Module (Join-Path $root 'scripts/lib/Common.psm1') -Force -DisableNameChecking
New-Item -ItemType Directory -Path $SaidaDir -Force | Out-Null
$falhas = New-Object Collections.Generic.List[string]

function Invoke-Fase {
    param([string]$Nome, [hashtable]$Parametros)
    $dir = Join-Path $SaidaDir $Nome
    Write-Information "`n===== $Nome =====" -InformationAction Continue
    & $main @Parametros -OutputDirectory $dir
    $code = $LASTEXITCODE
    $run = Get-ChildItem -LiteralPath $dir -Directory | Sort-Object Name | Select-Object -Last 1
    $resultado = Get-Content -LiteralPath (Join-Path $run.FullName 'resultados.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Write-Information "$Nome -> código $code ($($run.FullName))" -InformationAction Continue
    if ($code -notin 0, 1) { $falhas.Add("$Nome terminou com código $code") }
    return [pscustomobject]@{ Codigo = $code; Pasta = $run.FullName; Resultado = $resultado }
}

# ---- Preparação
if ($PrepararNaoConformidades) {
    $guest = Get-LocalUser | Where-Object { $_.SID.Value.EndsWith('-501') }
    if ($guest -and -not $guest.Enabled) { Enable-LocalUser -SID $guest.SID; Write-Information 'Convidado habilitado para o teste.' -InformationAction Continue }
    try {
        $telnet = Get-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction Stop
        if ($telnet.State -ne 'Enabled') {
            $null = Enable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart -ErrorAction Stop
            Write-Information 'TelnetClient habilitado para o teste.' -InformationAction Continue
        }
    } catch { Write-Warning "TelnetClient indisponível nesta imagem: $($_.Exception.Message)" }
}

# ---- Perfil e aprovação temporários para esta máquina
$perfil = Read-HWJson -Path (Join-Path $root 'scripts/config/perfil-academico.example.json')
$perfil.Accounts.AdministratorNewName = $NovoNomeAdministrador
$perfil.Accounts.ApprovedAdministrators = @(Get-HWLocalGroupMemberList -GroupSid 'S-1-5-32-544' | ForEach-Object { ($_.Name -split '\\')[-1] })
$perfil.Features.ApprovedToDisable = @($perfil.Features.Candidates)
$perfilPath = Join-Path $SaidaDir 'perfil-ciclo.json'
Save-HWJson -Path $perfilPath -InputObject $perfil

$aplicaveis = @(Get-HWControlCatalog | Where-Object { $_.Tipo -eq 'Aplicavel' } | ForEach-Object { $_.Id })
$aprovacao = [pscustomobject]@{
    Responsavel                  = 'Ciclo automatizado de laboratório'
    Maquina                      = $env:COMPUTERNAME
    ValidaAte                    = (Get-Date).AddDays(1).ToString('yyyy-MM-dd')
    AmbienteDeLaboratorio        = $true
    SnapshotConfirmado           = $true
    ContaDeRecuperacaoConfirmada = $true
    PermitirMaquinaFisica        = $false
    ControlesAprovados           = $aplicaveis
    Observacoes                  = 'Gerado por tests/Invoke-CicloLaboratorio.ps1'
}
$aprovacaoPath = Join-Path $SaidaDir 'aprovacao-ciclo.json'
Save-HWJson -Path $aprovacaoPath -InputObject $aprovacao

# ---- 1 Auditar · 2-4 Aplicar · 5 Verificar · Restaurar · Auditar de novo
$antes = Invoke-Fase -Nome '1-auditoria-inicial' -Parametros @{ Mode = 'Audit'; ProfilePath = $perfilPath }
$simulacao = Invoke-Fase -Nome '2-simulacao' -Parametros @{ Mode = 'Apply'; ProfilePath = $perfilPath; ApprovalPath = $aprovacaoPath; WhatIf = $true }
$aplicacao = Invoke-Fase -Nome '3-aplicacao' -Parametros @{ Mode = 'Apply'; ProfilePath = $perfilPath; ApprovalPath = $aprovacaoPath; Confirm = $false }
$restauracao = Invoke-Fase -Nome '4-restauracao' -Parametros @{ Mode = 'Rollback'; ProfilePath = $perfilPath; BackupPath = (Join-Path $aplicacao.Pasta 'backup'); Confirm = $false }
$depois = Invoke-Fase -Nome '5-auditoria-final' -Parametros @{ Mode = 'Audit'; ProfilePath = $perfilPath }

# ---- Conferências
foreach ($row in $simulacao.Resultado.Controles) {
    if ($row.Acao -eq 'Aplicado') { $falhas.Add("Simulação alterou o controle $($row.Id)") }
}
foreach ($row in $aplicacao.Resultado.Controles) {
    if ($row.Acao -eq 'Erro') { $falhas.Add("Aplicação do controle $($row.Id) falhou: $($row.Mensagem)") }
    if ($row.Tipo -eq 'Aplicavel' -and $row.StatusDepois -notin 'Conforme', 'Revisar') {
        $falhas.Add("Controle $($row.Id) ficou $($row.StatusDepois) depois de aplicar: $(@($row.Achados) -join ' | ')")
    }
}
foreach ($row in $restauracao.Resultado.Controles) {
    if ($row.Acao -eq 'Erro') { $falhas.Add("Restauração do controle $($row.Id) falhou: $($row.Mensagem)") }
}
$alterados = @($aplicacao.Resultado.Controles | Where-Object { $_.Acao -eq 'Aplicado' } | ForEach-Object { $_.Id })
foreach ($id in $alterados) {
    $a = @($antes.Resultado.Controles | Where-Object { $_.Id -eq $id })[0].Antes.Observed
    $d = @($depois.Resultado.Controles | Where-Object { $_.Id -eq $id })[0].Antes.Observed
    switch ($id) {
        '14' { $a = $a.Auditoria; $d = $d.Auditoria }
        '15' { $a = $a.Recursos; $d = $d.Recursos }
    }
    $ja = ConvertTo-Json -InputObject $a -Depth 8 -Compress
    $jd = ConvertTo-Json -InputObject $d -Depth 8 -Compress
    if ($ja -ne $jd) { $falhas.Add("Controle ${id} não voltou ao estado inicial. Antes: $ja · Depois: $jd") }
    else { Write-Information "Controle ${id}: restaurado ao estado inicial." -InformationAction Continue }
}

Write-Information "`nControles aplicados e restaurados: $($alterados -join ', ')" -InformationAction Continue
if ($falhas.Count -gt 0) {
    $falhas | ForEach-Object { Write-Warning $_ }
    exit 1
}
Write-Information 'Ciclo de laboratório concluído sem falhas.' -InformationAction Continue
exit 0
