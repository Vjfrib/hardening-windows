# Item 12 - Controlar as portas de rede abertas (checklist, seção 3.6)
#   Automático: Firewall do Windows ligado nos três perfis, com entrada bloqueada por padrão.
#   Revisão:    portas TCP em escuta fora de PortasPermitidas (configuração). O script
#               não fecha portas sozinho: isso depende da lista da ATI-PE.
@{
    Id       = 12
    Secao    = '3.6 Lacunas apontadas pela ATI-PE'
    Nome     = 'Controlar as portas de rede abertas'
    Esperado = { param($Cfg) 'Firewall ligado nos 3 perfis, entrada bloqueada; só portas aprovadas' }
    Testar   = {
        param($Cfg)
        $perfis = Get-NetFirewallProfile -PolicyStore ActiveStore
        $problemas = @()
        $resumo = foreach ($perfil in $perfis) {
            $ligado = "$($perfil.Enabled)"
            $entrada = "$($perfil.DefaultInboundAction)"
            if ($ligado -ne 'True') { $problemas += "Perfil $($perfil.Name) desligado ($ligado)." }
            if ($entrada -ne 'Block') { $problemas += "Perfil $($perfil.Name) com entrada '$entrada'." }
            "$($perfil.Name): ligado=$ligado, entrada=$entrada"
        }

        $portas = @(Get-PortasEmEscuta -IgnorarDinamicas $Cfg.IgnorarPortasDinamicas)
        Save-Evidencia -Nome 'item12-portas-em-escuta.csv' -Dados $portas
        $listaPortas = ($portas | ForEach-Object { "$($_.Porta) ($($_.Processo))" } | Select-Object -Unique) -join ', '

        $revisar = @()
        if ($Cfg.PortasPermitidas.Count -eq 0) {
            $revisar += "Lista de portas permitidas não definida. Portas TCP em escuta: $listaPortas."
        } else {
            $foraDaLista = @($portas | Where-Object { $Cfg.PortasPermitidas -notcontains $_.Porta })
            if ($foraDaLista.Count) {
                $revisar += "Portas em escuta fora da lista: $((($foraDaLista | ForEach-Object { "$($_.Porta) ($($_.Processo))" }) | Select-Object -Unique) -join ', ')."
            }
        }

        $status = if ($problemas.Count) { 'FALHA' } elseif ($revisar.Count) { 'REVISAR' } else { 'OK' }
        New-Resultado -Status $status -Valor ($resumo -join '; ') -Detalhes ((@($problemas) + @($revisar)) -join ' ')
    }
    Aplicar  = {
        param($Cfg)
        Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
    }
}
