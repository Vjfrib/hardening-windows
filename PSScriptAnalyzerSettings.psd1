@{
    # Regras do PSScriptAnalyzer usadas por tests/Test-Static.ps1 e pela CI.
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Set-HWSecurityValues aplica várias chaves de uma vez; o nome no plural é intencional
        # e aparece nos slides da apresentação.
        'PSUseSingularNouns'
    )
    Rules        = @{
        # Sintaxe válida no Windows PowerShell 5.1 e no PowerShell 7.
        PSUseCompatibleSyntax   = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
        # Comandos e tipos existentes no Windows PowerShell 5.1 do Windows 10/Server 2019 (build 17763).
        PSUseCompatibleCommands = @{
            Enable         = $true
            TargetProfiles = @('win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework')
        }
        PSUseCompatibleTypes    = @{
            Enable         = $true
            TargetProfiles = @('win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework')
        }
    }
}
