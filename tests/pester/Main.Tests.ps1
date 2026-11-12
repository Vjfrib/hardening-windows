#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Comportamento do ponto de entrada fora do Windows e na validação de parâmetros.

BeforeAll {
    $script:Root = Resolve-Path (Join-Path $PSScriptRoot '../..')
    $script:Main = Join-Path $script:Root 'Main.ps1'
    $script:OnWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    $script:Shell = (Get-Process -Id $PID).Path
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
        $out = & $script:Shell -NoProfile -NonInteractive -File $script:Main -ControlIds '17' 2>&1
        $LASTEXITCODE | Should -Not -Be 0
        ($out -join ' ') | Should -Match 'ControlIds'
    }
    It 'bloqueia com código 3 fora do Windows, sem tocar em nada' -Skip:$script:OnWindows {
        $out = Join-Path $TestDrive 'saida'
        $log = & $script:Shell -NoProfile -NonInteractive -File $script:Main -OutputDirectory $out 2>&1
        $LASTEXITCODE | Should -Be 3
        ($log -join ' ') | Should -Match 'só roda no Windows'
        $run = @(Get-ChildItem -LiteralPath $out -Directory)
        $run.Count | Should -Be 1
        (Get-Content -LiteralPath (Join-Path $run[0].FullName 'execucao.log') -Raw) | Should -Match 'Execução bloqueada'
    }
    It 'bloqueia com código 3 quando o perfil é inválido' {
        $bad = Join-Path $TestDrive 'perfil.json'
        '{ "Password": { "MinimumPasswordLength": 6 } }' | Set-Content -LiteralPath $bad
        $null = & $script:Shell -NoProfile -NonInteractive -File $script:Main -ProfilePath $bad -OutputDirectory (Join-Path $TestDrive 'x') 2>&1
        $LASTEXITCODE | Should -Be 3
    }
}
