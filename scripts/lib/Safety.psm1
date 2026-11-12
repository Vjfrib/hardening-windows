#Requires -Version 5.1
<#
    Safety.psm1 · travas verificadas antes de qualquer alteração.

    Aplicar exige, ao mesmo tempo:
      - Windows 10/11 ou Windows Server compatível (build >= 10240), fora de domínio;
      - PowerShell como Administrador (Windows PowerShell 5.1);
      - arquivo de aprovação assinado por um responsável, para ESTA máquina, dentro da validade,
        confirmando laboratório, snapshot externo e conta de recuperação;
      - máquina virtual (ou autorização explícita para máquina física);
      - o ID do controle listado em ControlesAprovados;
      - nenhuma outra aplicação ou restauração em andamento (mutex global).
#>
Set-StrictMode -Version Latest

$script:HWApprovalFields = @(
    'Responsavel', 'Maquina', 'ValidaAte', 'AmbienteDeLaboratorio', 'SnapshotConfirmado',
    'ContaDeRecuperacaoConfirmada', 'PermitirMaquinaFisica', 'ControlesAprovados'
)

function Assert-HWSupportedPlatform {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Machine,
        [Parameter(Mandatory)][ValidateSet('Audit', 'Apply', 'Rollback')][string]$Mode
    )
    if ($Machine.OsBuild -lt 10240) {
        throw "Windows build $($Machine.OsBuild) não é suportado: use Windows 10/11 Pro ou Windows Server compatível."
    }
    if ($Mode -eq 'Audit') { return }
    if ($Machine.ProductType -eq 2) {
        throw 'Controlador de domínio: a política local é a do domínio. Alterações devem ser feitas por GPO.'
    }
    if ($Machine.PartOfDomain) {
        throw "Máquina no domínio '$($Machine.Domain)': GPO pode sobrescrever a política local. Alterações só em workgroup (laboratório)."
    }
    if ($Machine.PSEdition -eq 'Core') {
        throw 'Use o Windows PowerShell 5.1 (powershell.exe) para alterar; LocalAccounts e secedit foram validados nele.'
    }
}

function Assert-HWApproval {
    <#
        Valida o arquivo de aprovação e devolve os IDs que podem ser alterados nesta execução.
        Lança exceção (execução bloqueada) se alguma condição geral falhar.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]$Approval,
        [Parameter(Mandatory)]$Machine,
        [Parameter(Mandatory)][string[]]$RequestedIds,
        [Parameter(Mandatory)][string[]]$ApplicableIds,
        [datetime]$Today = (Get-Date).Date
    )
    foreach ($field in $script:HWApprovalFields) {
        if ($null -eq $Approval.PSObject.Properties[$field]) { throw "Aprovação sem o campo '$field'." }
    }
    if ([string]::IsNullOrWhiteSpace([string]$Approval.Responsavel)) { throw 'Aprovação sem responsável.' }
    if ([string]$Approval.Maquina -ne [string]$Machine.ComputerName) {
        throw "Aprovação é para '$($Approval.Maquina)', mas esta máquina é '$($Machine.ComputerName)'."
    }
    $limit = [datetime]::MinValue
    if (-not [datetime]::TryParseExact([string]$Approval.ValidaAte, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None, [ref]$limit)) {
        throw 'ValidaAte deve estar no formato AAAA-MM-DD.'
    }
    if ($limit.Date -lt $Today.Date) { throw "Aprovação vencida em $($Approval.ValidaAte)." }
    if ($Approval.AmbienteDeLaboratorio -ne $true) { throw 'Confirme AmbienteDeLaboratorio=true (somente laboratório).' }
    if ($Approval.SnapshotConfirmado -ne $true) { throw 'Confirme SnapshotConfirmado=true: tire um snapshot da VM antes de aplicar.' }
    if ($Approval.ContaDeRecuperacaoConfirmada -ne $true) { throw 'Confirme ContaDeRecuperacaoConfirmada=true (outra conta administradora testada).' }
    if (-not $Machine.IsVirtual -and $Approval.PermitirMaquinaFisica -ne $true) {
        throw "A máquina não parece virtual ($($Machine.Manufacturer) / $($Machine.Model)). Aplique em VM ou autorize PermitirMaquinaFisica."
    }
    $approved = @($Approval.ControlesAprovados | ForEach-Object { '{0:D2}' -f [int]$_ })
    return @($RequestedIds | Where-Object { $_ -in $approved -and $_ -in $ApplicableIds })
}

function Enter-HWLock {
    <# Impede duas aplicações/restaurações simultâneas na mesma máquina. #>
    [CmdletBinding()]
    [OutputType([Threading.Mutex])]
    param([string]$Name = 'Global\UPE.HardeningWindows')
    $mutex = New-Object Threading.Mutex($false, $Name)
    $owned = $false
    try { $owned = $mutex.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $owned = $true }
    if (-not $owned) {
        $mutex.Dispose()
        throw 'Outra aplicação ou restauração está em andamento nesta máquina.'
    }
    return $mutex
}

function Exit-HWLock {
    [CmdletBinding()]
    param([AllowNull()][Threading.Mutex]$Mutex)
    if ($null -eq $Mutex) { return }
    try { $Mutex.ReleaseMutex() } catch { Write-Verbose 'Mutex já liberado.' }
    $Mutex.Dispose()
}

Export-ModuleMember -Function 'Assert-HWSupportedPlatform', 'Assert-HWApproval', 'Enter-HWLock', 'Exit-HWLock'
