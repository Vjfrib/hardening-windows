Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:PolicyKeys = @{
    '01' = 'MinimumPasswordLength'
    '02' = 'PasswordComplexity'
    '03' = 'PasswordHistorySize'
}
$script:PolicyRanges = @{
    MinimumPasswordLength = @(0, 128)
    PasswordComplexity = @(0, 1)
    PasswordHistorySize = @(0, 24)
    MinimumPasswordAge = @(0, 999)
    MaximumPasswordAge = @(-1, 999)
    LockoutBadCount = @(0, 999)
    LockoutDuration = @(-1, 99999)
    ResetLockoutCount = @(0, 99999)
}
$script:AuditGuids = @{
    Logon = '0cce9215-69ae-11d9-bed3-505054503030'
    UserAccounts = '0cce9235-69ae-11d9-bed3-505054503030'
    SecurityGroups = '0cce9237-69ae-11d9-bed3-505054503030'
}
$script:UacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$script:UacLimits = [ordered]@{
    EnableLUA = 1
    ConsentPromptBehaviorAdmin = 5
    PromptOnSecureDesktop = 1
}

function Read-HWRollbackInteger($Value, [string]$Name, [int]$Minimum, [int]$Maximum) {
    $number = 0
    if ($null -eq $Value -or -not [int]::TryParse([string]$Value, [ref]$number) -or
        $number -lt $Minimum -or $number -gt $Maximum) {
        throw "Valor de rollback ausente ou invalido: $Name."
    }
    return $number
}

function Read-HWRollbackPolicyValue([string]$Key, $Value) {
    $range = $script:PolicyRanges[$Key]
    $number = Read-HWRollbackInteger $Value $Key $range[0] $range[1]
    if ($number -eq 0 -and $Key -in @('MaximumPasswordAge', 'LockoutDuration')) {
        throw "Valor de rollback invalido: $Key."
    }
    return $number
}

function Get-HWRollbackAccount([int]$Rid) {
    $user = Get-HWLocalUserByRid -Rid $Rid
    if ($null -eq $user) { throw "Conta local RID $Rid indisponivel para rollback." }
    return $user
}

function Get-HWRollbackAuditValue([string]$Name) {
    $value = Get-HWAuditSetting -Guid $script:AuditGuids[$Name]
    Read-HWRollbackInteger $value $Name 0 3
}

function Get-HWReversibleState {
    param([Parameter(Mandatory)][string]$Id)
    if ($script:PolicyKeys.ContainsKey($Id)) {
        $key = $script:PolicyKeys[$Id]
        $value = Get-HWPolicyInt -Policy (Get-HWLocalPolicy) -Key $key
        return [pscustomobject]@{ Value = Read-HWRollbackPolicyValue $key $value }
    }
    if ($Id -in '05','06') {
        $policy = Get-HWLocalPolicy
        return [pscustomobject][ordered]@{
            LockoutBadCount = Read-HWRollbackPolicyValue 'LockoutBadCount' (Get-HWPolicyInt $policy 'LockoutBadCount')
            LockoutDuration = Read-HWRollbackPolicyValue 'LockoutDuration' (Get-HWPolicyInt $policy 'LockoutDuration')
            ResetLockoutCount = Read-HWRollbackPolicyValue 'ResetLockoutCount' (Get-HWPolicyInt $policy 'ResetLockoutCount')
        }
    }

    switch ($Id) {
        '04' {
            $policy = Get-HWLocalPolicy
            return [pscustomobject][ordered]@{
                MaximumPasswordAge = Read-HWRollbackPolicyValue 'MaximumPasswordAge' (Get-HWPolicyInt $policy 'MaximumPasswordAge')
                MinimumPasswordAge = Read-HWRollbackPolicyValue 'MinimumPasswordAge' (Get-HWPolicyInt $policy 'MinimumPasswordAge')
            }
        }
        '07' {
            $user = Get-HWRollbackAccount 500
            return [pscustomobject][ordered]@{ SID = $user.SID.Value; Name = $user.Name }
        }
        '08' {
            $guest = Get-HWRollbackAccount 501
            return [pscustomobject][ordered]@{ SID = $guest.SID.Value; Enabled = $guest.Enabled }
        }
        '09' {
            $registryKey = Get-Item -LiteralPath $script:UacPath
            try {
                $state = [ordered]@{}
                $names = $registryKey.GetValueNames()
                foreach ($name in $script:UacLimits.Keys) {
                    if ($name -notin $names) { throw "Valor do UAC ausente: $name." }
                    if ($registryKey.GetValueKind($name) -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
                        throw "Tipo inesperado de valor no UAC: $name."
                    }
                    $state[$name] = Read-HWRollbackInteger ($registryKey.GetValue($name)) $name 0 $script:UacLimits[$name]
                }
                return [pscustomobject]$state
            } finally {
                $registryKey.Dispose()
            }
        }
        '11' {
            return [pscustomobject]@{ Logon = Get-HWRollbackAuditValue 'Logon' }
        }
        '14' {
            return [pscustomobject][ordered]@{
                UserAccounts = Get-HWRollbackAuditValue 'UserAccounts'
                SecurityGroups = Get-HWRollbackAuditValue 'SecurityGroups'
            }
        }
        default { throw "Controle $Id nao tem rollback automatico." }
    }
}

function Restore-HWReversibleState {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][psobject]$State
    )
    if ($script:PolicyKeys.ContainsKey($Id)) {
        $key = $script:PolicyKeys[$Id]
        $value = Read-HWRollbackPolicyValue $key $State.Value
        Set-HWSecurityValues -Values @{ $key = $value }
        return
    }

    switch ($Id) {
        '04' {
            $maximum = Read-HWRollbackPolicyValue 'MaximumPasswordAge' $State.MaximumPasswordAge
            $minimum = Read-HWRollbackPolicyValue 'MinimumPasswordAge' $State.MinimumPasswordAge
            if ($maximum -ne -1 -and $maximum -le $minimum) {
                throw 'Validade minima incompativel com a maxima anterior.'
            }
            Set-HWSecurityValues -Values @{ MaximumPasswordAge = $maximum } -Expected @{ MinimumPasswordAge = $minimum }
        }
        '05' {
            $threshold = Read-HWRollbackPolicyValue 'LockoutBadCount' $State.LockoutBadCount
            $duration = Read-HWRollbackPolicyValue 'LockoutDuration' $State.LockoutDuration
            $reset = Read-HWRollbackPolicyValue 'ResetLockoutCount' $State.ResetLockoutCount
            if ($threshold -gt 0 -and ($reset -lt 1 -or ($duration -ne -1 -and $reset -gt $duration))) {
                throw 'Estado de bloqueio anterior incompativel.'
            }
            Set-HWSecurityValues -Values @{ LockoutBadCount = $threshold } -Expected @{
                LockoutDuration = $duration; ResetLockoutCount = $reset
            }
        }
        '06' {
            $threshold = Read-HWRollbackPolicyValue 'LockoutBadCount' $State.LockoutBadCount
            $duration = Read-HWRollbackPolicyValue 'LockoutDuration' $State.LockoutDuration
            $reset = Read-HWRollbackPolicyValue 'ResetLockoutCount' $State.ResetLockoutCount
            if ($threshold -gt 0 -and ($reset -lt 1 -or ($duration -ne -1 -and $reset -gt $duration))) {
                throw 'Estado de bloqueio anterior incompativel.'
            }
            Set-HWSecurityValues -Values @{
                LockoutDuration = $duration; ResetLockoutCount = $reset
            } -Expected @{ LockoutBadCount = $threshold }
        }
        '07' {
            $user = Get-HWRollbackAccount 500
            $name = [string]$State.Name
            if ($user.SID.Value -ne $State.SID -or [string]::IsNullOrWhiteSpace($name)) {
                throw 'Conta ou nome invalido no rollback do Administrador.'
            }
            if ($user.Name -ceq $name) { return }
            if (@(Get-HWRecoveryAdministratorSid -Administrator $user).Count -eq 0) {
                throw 'Confirme outra conta administrativa local habilitada antes de renomear.'
            }
            if (Get-LocalUser | Where-Object { $_.Name -eq $name -and $_.SID.Value -ne $user.SID.Value }) {
                throw 'O nome anterior do Administrador ja pertence a outra conta.'
            }
            Rename-LocalUser -SID $user.SID -NewName $name
        }
        '08' {
            $guest = Get-HWRollbackAccount 501
            if ($guest.SID.Value -ne $State.SID -or $State.Enabled -isnot [bool]) {
                throw 'Conta ou estado invalido no rollback do Convidado.'
            }
            if ($guest.Enabled -eq $State.Enabled) { return }
            if ($State.Enabled) { Enable-LocalUser -SID $guest.SID }
            else { Disable-LocalUser -SID $guest.SID }
        }
        '09' {
            $values = [ordered]@{}
            foreach ($name in $script:UacLimits.Keys) {
                $values[$name] = Read-HWRollbackInteger $State.$name $name 0 $script:UacLimits[$name]
            }
            $current = Get-HWReversibleState -Id '09'
            foreach ($name in $values.Keys) {
                if ($values[$name] -eq $current.$name) { continue }
                Set-ItemProperty -LiteralPath $script:UacPath -Name $name -Value $values[$name] -Type DWord
            }
        }
        '11' {
            $logon = Read-HWRollbackInteger $State.Logon 'Logon' 0 3
            Set-HWAuditSetting -Guid $script:AuditGuids.Logon -Setting $logon
        }
        '14' {
            $accounts = Read-HWRollbackInteger $State.UserAccounts 'UserAccounts' 0 3
            $groups = Read-HWRollbackInteger $State.SecurityGroups 'SecurityGroups' 0 3
            Set-HWAuditSetting -Guid $script:AuditGuids.UserAccounts -Setting $accounts
            Set-HWAuditSetting -Guid $script:AuditGuids.SecurityGroups -Setting $groups
        }
        default { throw "Controle $Id nao tem rollback automatico." }
    }
}

Export-ModuleMember -Function Get-HWReversibleState,Restore-HWReversibleState
