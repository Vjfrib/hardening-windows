# Item 16 - Revisar e desativar contas de serviço sem uso (checklist, seção 3.6)
#   Automático: (1) desabilita e para os serviços de ServicosDesabilitar;
#               (2) nega logon local e por Área de Trabalho Remota às ContasDeServico;
#               (3) desabilita contas locais sem uso, se DesabilitarContasSemUso = $true.
#   Revisão:    serviços rodando com contas que não são do Windows e contas locais
#               sem logon há mais de DiasSemUsoConta dias.
@{
    Id       = 16
    Secao    = '3.6 Lacunas apontadas pela ATI-PE'
    Nome     = 'Revisar contas de serviço sem uso'
    Esperado = { param($Cfg) 'Serviços e contas sem uso desabilitados; contas de serviço sem logon interativo' }
    Testar   = {
        param($Cfg)
        $problemas = @()
        $revisar = @()

        $servicos = @(Get-CimInstance Win32_Service | Select-Object Name, DisplayName, StartMode, State, StartName)
        Save-Evidencia -Nome 'item16-servicos.csv' -Dados $servicos

        # (1) Serviços que deveriam estar desabilitados
        foreach ($nome in $Cfg.ServicosDesabilitar) {
            $servico = $servicos | Where-Object { $_.Name -eq $nome } | Select-Object -First 1
            if ($servico -and ($servico.StartMode -ne 'Disabled' -or $servico.State -eq 'Running')) {
                $problemas += "Serviço $nome está $($servico.StartMode)/$($servico.State)."
            }
        }

        # Serviços que rodam com contas que não são as do próprio Windows
        $contasDoWindows = '^(LocalSystem|NT AUTHORITY\\.+|NT SERVICE\\.+|NT AUTORIDADE\\.+)?$'
        $personalizadas = @($servicos | Where-Object { "$($_.StartName)" -notmatch $contasDoWindows })
        if ($personalizadas.Count) {
            $revisar += "Serviços com conta própria: $(($personalizadas | ForEach-Object { "$($_.Name) ($($_.StartName))" }) -join ', ')."
        }

        # (2) Contas de serviço sem logon interativo
        $negadoLocal = Get-DireitoUsuario -Direito 'SeDenyInteractiveLogonRight'
        $negadoRdp = Get-DireitoUsuario -Direito 'SeDenyRemoteInteractiveLogonRight'
        foreach ($conta in $Cfg.ContasDeServico) {
            $sid = ConvertTo-Sid $conta
            if ($negadoLocal -notcontains $sid -or $negadoRdp -notcontains $sid) {
                $problemas += "Conta de serviço $conta ainda pode fazer logon interativo."
            }
        }
        if ($personalizadas.Count -and $Cfg.ContasDeServico.Count -eq 0) {
            $revisar += 'Defina ContasDeServico na configuração para negar logon interativo a essas contas.'
        }

        # (3) Contas locais sem uso
        $limite = (Get-Date).AddDays(-$Cfg.DiasSemUsoConta)
        $atual = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $semUso = @(Get-LocalUser | Where-Object {
            $_.Enabled -and
            $_.SID.Value -notmatch '-(500|501|503|504)$' -and
            $_.SID.Value -ne $atual -and
            ($null -eq $_.LastLogon -or $_.LastLogon -lt $limite)
        })
        if ($semUso.Count) {
            $texto = "Contas locais sem logon há mais de $($Cfg.DiasSemUsoConta) dias: $(($semUso | ForEach-Object { $_.Name }) -join ', ')."
            if ($Cfg.DesabilitarContasSemUso) { $problemas += $texto } else { $revisar += $texto }
        }

        $status = if ($problemas.Count) { 'FALHA' } elseif ($revisar.Count) { 'REVISAR' } else { 'OK' }
        $valor = "$($servicos.Count) serviços; $($personalizadas.Count) com conta própria; $($semUso.Count) conta(s) local(is) sem uso"
        New-Resultado -Status $status -Valor $valor -Detalhes ((@($problemas) + @($revisar)) -join ' ')
    }
    Aplicar  = {
        param($Cfg)
        foreach ($nome in $Cfg.ServicosDesabilitar) {
            $servico = Get-Service -Name $nome -ErrorAction SilentlyContinue
            if ($servico) {
                Set-Service -Name $nome -StartupType Disabled
                if ($servico.Status -eq 'Running') { Stop-Service -Name $nome -Force }
            }
        }

        if ($Cfg.ContasDeServico.Count) {
            $sids = @($Cfg.ContasDeServico | ForEach-Object { ConvertTo-Sid $_ })
            foreach ($direito in @('SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight')) {
                $atuais = Get-DireitoUsuario -Direito $direito
                Set-DireitoUsuario -Direito $direito -Contas (@($atuais) + $sids | Select-Object -Unique)
            }
        }

        if ($Cfg.DesabilitarContasSemUso) {
            $limite = (Get-Date).AddDays(-$Cfg.DiasSemUsoConta)
            $atual = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            Get-LocalUser | Where-Object {
                $_.Enabled -and
                $_.SID.Value -notmatch '-(500|501|503|504)$' -and
                $_.SID.Value -ne $atual -and
                ($null -eq $_.LastLogon -or $_.LastLogon -lt $limite)
            } | ForEach-Object { Disable-LocalUser -SID $_.SID }
        }
    }
}
