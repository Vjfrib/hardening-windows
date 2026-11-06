Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Assert-HWWindows {
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Este projeto requer Windows; nenhuma mudanca foi aplicada.' }
}
function Test-HWAdministrator {
  $p=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
  $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Read-HWJson([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { throw "Arquivo nao encontrado: $Path" }
  Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}
function New-HWState {
  param([string]$Id,[string]$Name,$Current,$Expected,$Compliant,[string]$Note,[string]$Status='')
  if (-not $Status) {
    if ($null -eq $Compliant) { $Status='RequiresReview' }
    elseif ($Compliant) { $Status='Compliant' }
    else { $Status='NonCompliant' }
  }
  [pscustomobject]@{ Id=$Id; Control=$Name; Status=$Status; Compliant=$Compliant; Current=$Current; Expected=$Expected; Note=$Note; Timestamp=(Get-Date).ToString('o') }
}
function Get-HWLocalPolicy {
  param([switch]$MergedPolicy)
  $temp=Join-Path ([IO.Path]::GetTempPath()) ('hw-'+[guid]::NewGuid().ToString('N')+'.inf')
  try {
    $arguments=@('/export','/cfg',$temp,'/areas','SECURITYPOLICY','USER_RIGHTS','/quiet')
    if ($MergedPolicy) { $arguments+= '/mergedpolicy' }
    $out=& secedit.exe @arguments 2>&1
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $temp)) { throw "secedit /export falhou ($LASTEXITCODE): $out" }
    $result=@{}
    foreach ($line in (Get-Content -LiteralPath $temp)) {
      if ($line -match '^\s*([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$') { $result[$matches[1]]=$matches[2] }
    }
    return $result
  } finally { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false }
}
function Get-HWPolicyInt([hashtable]$Policy,[string]$Key) {
  if (-not $Policy.ContainsKey($Key)) { return $null }
  $number=0
  if ([int]::TryParse([string]$Policy[$Key],[ref]$number)) { return $number }
  return $null
}
function Set-HWSecurityValues {
  param([hashtable]$Values,[hashtable]$Expected=@{})
  $allowed=@{
    MinimumPasswordLength=0,128; PasswordComplexity=0,1; PasswordHistorySize=0,24
    MaximumPasswordAge=-1,999; LockoutBadCount=0,999
    LockoutDuration=-1,99999; ResetLockoutCount=0,99999
  }
  $local=Get-HWLocalPolicy
  $merged=Get-HWLocalPolicy -MergedPolicy
  foreach ($key in $Expected.Keys) {
    $observed=Get-HWPolicyInt -Policy $local -Key $key
    $effective=Get-HWPolicyInt -Policy $merged -Key $key
    if ($null -eq $observed -or $observed -ne $Expected[$key] -or $effective -ne $observed) {
      throw "Politica alterada ou sobrescrita para $key. Execute uma nova auditoria."
    }
  }
  $lines=@()
  foreach ($key in ($Values.Keys | Sort-Object)) {
    $value=0
    if (-not $allowed.ContainsKey($key) -or -not [int]::TryParse([string]$Values[$key],[ref]$value) -or
        $value -lt $allowed[$key][0] -or $value -gt $allowed[$key][1]) {
      throw "Valor fora do escopo para $key."
    }
    $previous=Get-HWPolicyInt -Policy $local -Key $key
    $effective=Get-HWPolicyInt -Policy $merged -Key $key
    if ($null -eq $previous -or $null -eq $effective -or $previous -ne $effective) {
      throw "Politica local e efetiva ausentes ou divergentes para $key. Revise a GPO."
    }
    if ($previous -ne $value) { $lines+= "$key = $value" }
  }
  if ($lines.Count -eq 0) { return }
  $prefix=Join-Path ([IO.Path]::GetTempPath()) ('hw-'+[guid]::NewGuid().ToString('N'))
  $inf="$prefix.inf"; $db="$prefix.sdb"; $log="$prefix.log"
  try {
    (@('[Unicode]','Unicode=yes','[Version]','signature="$CHICAGO$"','Revision=1','[System Access]') + $lines) |
      Set-Content -LiteralPath $inf -Encoding Unicode
    $out=& secedit.exe /configure /db $db /cfg $inf /overwrite /areas SECURITYPOLICY /log $log /quiet 2>&1
    if ($LASTEXITCODE -ne 0) { throw "secedit /configure falhou ($LASTEXITCODE): $out" }
  } finally {
    foreach($path in @($inf,$db,$log,"$prefix.jfm")){ Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
  }
}
function Get-HWLocalUserByRid([int]$Rid) {
  if ($Rid -notin @(500,501)) { throw 'RID inesperado' }
  if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) { throw 'Get-LocalUser indisponivel; use PowerShell 64 bits com Microsoft.PowerShell.LocalAccounts.' }
  Get-LocalUser | Where-Object { $_.SID.Value -match "-$Rid`$" } | Select-Object -First 1
}
function Get-HWRecoveryAdministratorSid {
  param($Administrator)
  $administrators=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
  $localSid=$Administrator.SID.AccountDomainSid
  foreach ($member in (Get-LocalGroupMember -SID $administrators -ErrorAction Stop)) {
    if ($member.SID -eq $Administrator.SID -or $member.SID.AccountDomainSid -ne $localSid -or
        $member.ObjectClass -ne 'User') { continue }
    $account=Get-LocalUser -SID $member.SID -ErrorAction Stop
    if ($account.Enabled) { $account.SID.Value }
  }
}
function Get-HWAuditSetting([string]$Guid) {
  if (-not ('HardeningWindows.NativeAudit' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace HardeningWindows
{
    public static class NativeAudit
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct AuditPolicyInformation
        {
            internal Guid Subcategory;
            internal uint Flags;
            internal Guid Category;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool AuditQuerySystemPolicy(
            ref Guid subcategory, uint count, out IntPtr policy);

        [DllImport("advapi32.dll")]
        private static extern void AuditFree(IntPtr policy);

        public static int Query(Guid subcategory)
        {
            IntPtr policy;
            if (!AuditQuerySystemPolicy(ref subcategory, 1, out policy))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            try
            {
                var value = (AuditPolicyInformation)Marshal.PtrToStructure(
                    policy, typeof(AuditPolicyInformation));
                return (int)(value.Flags & 3);
            }
            finally
            {
                AuditFree(policy);
            }
        }
    }
}
'@ -ErrorAction Stop
  }
  [HardeningWindows.NativeAudit]::Query([guid]$Guid)
}
function Set-HWAuditSetting {
  param([string]$Guid,[ValidateRange(0,3)][int]$Setting=3)
  $success=if ($Setting -band 1) { 'enable' } else { 'disable' }
  $failure=if ($Setting -band 2) { 'enable' } else { 'disable' }
  $out=& auditpol.exe /set "/subcategory:{$Guid}" "/success:$success" "/failure:$failure" 2>&1
  if ($LASTEXITCODE -ne 0) { throw "auditpol /set falhou: $out" }
}
function Test-HWDomainMember {
  try {
    $domain=(Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain
    if ($domain -is [bool]) { $domain }
  }
  catch { $null }
}
function Get-HWEventSample([string]$LogName,[int[]]$Id) {
  $filter=@{LogName=$LogName;Id=$Id;StartTime=(Get-Date).AddDays(-7)}
  try {
    Get-WinEvent -FilterHashtable $filter -MaxEvents 1000 -ErrorAction Stop |
      ForEach-Object {
        try { [pscustomobject]@{Id=$_.Id;LogName=$_.LogName;TimeCreated=$_.TimeCreated;RecordId=$_.RecordId} }
        finally { $_.Dispose() }
      }
  } catch {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound,*') { throw }
  }
}
Export-ModuleMember -Function Assert-HWWindows,Test-HWAdministrator,Read-HWJson,New-HWState,Get-HWLocalPolicy,Get-HWPolicyInt,Set-HWSecurityValues,Get-HWLocalUserByRid,Get-HWRecoveryAdministratorSid,Get-HWAuditSetting,Set-HWAuditSetting,Test-HWDomainMember,Get-HWEventSample
