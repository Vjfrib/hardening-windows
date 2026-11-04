# Item 10 - Restringir o uso de contas locais em rede (checklist, seção 3.4)
#   - Direito "Negar acesso a este computador pela rede" (SeDenyNetworkLogonRight)
#     com as contas de ContasNegadasNaRede (configuração).
#   - Modelo de compartilhamento e segurança para contas locais = Clássico (ForceGuest = 0).
#   - Restrições do UAC para contas locais em logon de rede (LocalAccountTokenFilterPolicy = 0).
@{
    Id       = 10
    Secao    = '3.4 Controle de privilégios e acesso'
    Nome     = 'Restringir contas locais em rede'
    Esperado = { param($Cfg) "Negar acesso pela rede a: $(($Cfg.ContasNegadasNaRede | ForEach-Object { ConvertTo-NomeConta (ConvertTo-Sid $_) }) -join ', ')" }
    Testar   = {
        param($Cfg)
        $atuais = Get-DireitoUsuario -Direito 'SeDenyNetworkLogonRight'
        $faltando = @($Cfg.ContasNegadasNaRede | ForEach-Object { ConvertTo-Sid $_ } | Where-Object { $atuais -notcontains $_ })
        $forceGuest = Get-ValorRegistro -Caminho 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Nome 'ForceGuest'
        $tokenFilter = Get-ValorRegistro -Caminho 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Nome 'LocalAccountTokenFilterPolicy'
        $problemas = @()
        if ($faltando.Count) { $problemas += "Falta negar acesso pela rede a: $(Format-ListaContas $faltando)." }
        if ($forceGuest -eq 1) { $problemas += 'Modelo de compartilhamento está como "Somente convidado" (ForceGuest=1).' }
        if ($tokenFilter -eq 1) { $problemas += 'LocalAccountTokenFilterPolicy=1 libera administradores locais pela rede.' }
        New-Resultado -Conforme ($problemas.Count -eq 0) -Valor "Negado pela rede: $(Format-ListaContas $atuais)" -Detalhes ($problemas -join ' ')
    }
    Aplicar  = {
        param($Cfg)
        $atuais = Get-DireitoUsuario -Direito 'SeDenyNetworkLogonRight'
        $novos = @($atuais) + @($Cfg.ContasNegadasNaRede | ForEach-Object { ConvertTo-Sid $_ })
        Set-DireitoUsuario -Direito 'SeDenyNetworkLogonRight' -Contas ($novos | Select-Object -Unique)
        Set-ValorRegistro -Caminho 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Nome 'ForceGuest' -Valor 0
        Set-ValorRegistro -Caminho 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Nome 'LocalAccountTokenFilterPolicy' -Valor 0
    }
}
