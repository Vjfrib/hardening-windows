# Item 13 - Proteger os arquivos de log e o direito de apagá-los (checklist, seção 3.6)
#   Automático: (1) só SYSTEM, Administradores e o serviço de log podem escrever ou
#               apagar em C:\Windows\System32\winevt\Logs;
#               (2) "Gerenciar auditoria e log de segurança" (SeSecurityPrivilege)
#               só para Administradores.
#   Revisão:    (3) encaminhamento dos logs para um servidor central (depende da ATI-PE).
#   Os eventos 1102 (log de Segurança limpo) e 104 (log de Sistema limpo) são gerados
#   pelo próprio Windows; o alerta sobre eles fica no servidor central.
@{
    Id       = 13
    Secao    = '3.6 Lacunas apontadas pela ATI-PE'
    Nome     = 'Proteger os arquivos de log'
    Esperado = { param($Cfg) 'Escrita/limpeza só para SYSTEM e Administradores; cópia central' }
    Testar   = {
        param($Cfg)
        $pasta = Join-Path $env:windir 'System32\winevt\Logs'
        $permitidos = @($script:SID.Sistema, $script:SID.Administradores, $script:SID.EventLog, $script:SID.TrustedInstaller)
        # Direitos que permitem alterar ou apagar, incluindo os genéricos (GENERIC_ALL e GENERIC_WRITE).
        $mascara = [int]([Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership') -bor 0x10000000 -bor 0x40000000

        $acl = Get-Acl -Path $pasta
        $linhasAcl = @()
        $indevidos = @()
        foreach ($regra in $acl.Access) {
            $linhasAcl += "$($regra.IdentityReference): $($regra.AccessControlType) $($regra.FileSystemRights)"
            if ("$($regra.AccessControlType)" -ne 'Allow') { continue }
            try {
                $sid = $regra.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            } catch {
                $sid = "$($regra.IdentityReference)"
            }
            if ($permitidos -contains $sid) { continue }
            if (([int]$regra.FileSystemRights -band $mascara) -ne 0) {
                $indevidos += [pscustomobject]@{ Sid = $sid; Conta = "$($regra.IdentityReference)"; Herdada = $regra.IsInherited }
            }
        }
        Save-Evidencia -Nome 'item13-permissoes-winevt-logs.txt' -Dados $linhasAcl

        $direito = Get-DireitoUsuario -Direito 'SeSecurityPrivilege'
        $direitoOk = ($direito.Count -ge 1) -and (@($direito | Where-Object { $_ -ne $script:SID.Administradores }).Count -eq 0)

        $coletor = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' -ErrorAction SilentlyContinue

        $problemas = @()
        if ($indevidos.Count) { $problemas += "Podem alterar/apagar logs: $((($indevidos | ForEach-Object { $_.Conta }) | Select-Object -Unique) -join ', ')." }
        if (-not $direitoOk) { $problemas += "SeSecurityPrivilege com: $(Format-ListaContas $direito)." }
        $revisar = @()
        if (-not $coletor) { $revisar += 'Encaminhamento para servidor central de logs não configurado (definir com a ATI-PE).' }

        $status = if ($problemas.Count) { 'FALHA' } elseif ($revisar.Count) { 'REVISAR' } else { 'OK' }
        $valor = "ACL: $(if ($indevidos.Count) { "$($indevidos.Count) conta(s) a mais" } else { 'restrita' }); auditoria e log: $(Format-ListaContas $direito)"
        New-Resultado -Status $status -Valor $valor -Detalhes ((@($problemas) + @($revisar)) -join ' ')
    }
    Aplicar  = {
        param($Cfg)
        $pasta = Join-Path $env:windir 'System32\winevt\Logs'
        $permitidos = @($script:SID.Sistema, $script:SID.Administradores, $script:SID.EventLog, $script:SID.TrustedInstaller)
        $mascara = [int]([Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership') -bor 0x10000000 -bor 0x40000000
        foreach ($regra in (Get-Acl -Path $pasta).Access) {
            if ("$($regra.AccessControlType)" -ne 'Allow' -or $regra.IsInherited) { continue }
            try { $sid = $regra.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { continue }
            if ($permitidos -contains $sid) { continue }
            if (([int]$regra.FileSystemRights -band $mascara) -ne 0) {
                # Remove as permissões dessa conta na pasta (ela continua podendo ler pelo log de eventos).
                Invoke-Programa -Programa 'icacls.exe' -Argumentos @($pasta, '/remove:g', "*$sid") | Out-Null
            }
        }
        Set-DireitoUsuario -Direito 'SeSecurityPrivilege' -Contas @($script:SID.Administradores)
    }
}
