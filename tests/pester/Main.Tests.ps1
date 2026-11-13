#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Comportamento do ponto de entrada fora do Windows e na validação de parâmetros.

BeforeAll {
    $script:Root = Resolve-Path (Join-Path $PSScriptRoot '../..')
    $script:Main = Join-Path $script:Root 'Main.ps1'
    $script:Shell = (Get-Process -Id $PID).Path
    # No Windows PowerShell 5.1, stderr de processo filho com 2>&1 vira exceção se a preferência for Stop.
    $script:Run = {
        param([string[]]$Arguments)
        $ErrorActionPreference = 'Continue'
        $lines = & $script:Shell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script:Main @Arguments 2>&1 | ForEach-Object { "$_" }
        [pscustomobject]@{ Code = $LASTEXITCODE; Text = ($lines -join ' ') }
    }
}

Describe 'Main.ps1' {
    It 'tem SupportsShouldProcess (-WhatIf/-Confirm) e modo padrão Audit' {
        $cmd = Get-Command $script:Main
        $cmd.Parameters.ContainsKey('WhatIf') | Should -BeTrue
        $cmd.Parameters.ContainsKey('Confirm') | Should -BeTrue
        $ast = [Management.Automation.Language.Parser]::ParseFile($script:Main, [ref]$null, [ref]$null)
        $mode = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Mode' }
        $mode.DefaultValue.Value | Should -Be 'Audit'
    }
    It 'recusa ID fora de 01-16' {
        $r = & $script:Run @('-ControlIds', '17')
        $r.Code | Should -Not -Be 0
        $r.Text | Should -Match 'ControlIds'
    }
    It 'bloqueia com código 3 fora do Windows, sem tocar em nada' -Skip:([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {   # avaliado na descoberta
        $out = Join-Path $TestDrive 'saida'
        $r = & $script:Run @('-OutputDirectory', $out)
        $r.Code | Should -Be 3
        $r.Text | Should -Match 'só roda no Windows'
        $run = @(Get-ChildItem -LiteralPath $out -Directory)
        $run.Count | Should -Be 1
        (Get-Content -LiteralPath (Join-Path $run[0].FullName 'execucao.log') -Raw) | Should -Match 'Execução bloqueada'
    }
    It 'bloqueia com código 3 quando o perfil é inválido' {
        $bad = Join-Path $TestDrive 'perfil.json'
        '{ "Password": { "MinimumPasswordLength": 6 } }' | Set-Content -LiteralPath $bad
        $r = & $script:Run @('-ProfilePath', $bad, '-OutputDirectory', (Join-Path $TestDrive 'x'))
        $r.Code | Should -Be 3
    }
}
