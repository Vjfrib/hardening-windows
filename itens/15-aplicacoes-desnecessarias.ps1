# Item 15 - Remover aplicações e recursos desnecessários (checklist, seção 3.6)
#   Automático: desativa os recursos opcionais de RecursosDesabilitar (SMB 1.0, Telnet, TFTP).
#   Revisão:    inventário das aplicações instaladas comparado com AplicacoesAprovadas.
#               O script não desinstala aplicações: o checklist pede confirmar com os
#               usuários antes de remover.
@{
    Id       = 15
    Secao    = '3.6 Lacunas apontadas pela ATI-PE'
    Nome     = 'Remover aplicações e recursos desnecessários'
    Esperado = { param($Cfg) "Recursos desativados: $($Cfg.RecursosDesabilitar -join ', '); só aplicações aprovadas" }
    Testar   = {
        param($Cfg)
        $problemas = @()
        $estados = @()
        foreach ($nome in $Cfg.RecursosDesabilitar) {
            $recurso = $null
            try { $recurso = Get-WindowsOptionalFeature -Online -FeatureName $nome -ErrorAction SilentlyContinue } catch { $recurso = $null }
            if (-not $recurso) {
                $estados += "${nome}: não existe nesta edição"
                continue
            }
            $estados += "${nome}: $($recurso.State)"
            if ("$($recurso.State)" -in @('Enabled', 'EnablePending')) { $problemas += "Recurso $nome está ativo." }
        }

        $chaves = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $aplicacoes = @(Get-ItemProperty -Path $chaves -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and $_.SystemComponent -ne 1 } |
            Select-Object @{ n = 'Nome'; e = { $_.DisplayName } }, @{ n = 'Versao'; e = { $_.DisplayVersion } }, @{ n = 'Fabricante'; e = { $_.Publisher } } |
            Sort-Object Nome -Unique)
        Save-Evidencia -Nome 'item15-aplicacoes-instaladas.csv' -Dados $aplicacoes
        Save-Evidencia -Nome 'item15-recursos.txt' -Dados $estados

        $revisar = @()
        if ($Cfg.AplicacoesAprovadas.Count -eq 0) {
            $revisar += "Lista de aplicações aprovadas não definida; $($aplicacoes.Count) aplicações instaladas (veja a evidência do item 15)."
        } else {
            $naoAprovadas = @($aplicacoes | Where-Object {
                $app = $_.Nome
                -not ($Cfg.AplicacoesAprovadas | Where-Object { $app -like $_ })
            })
            if ($naoAprovadas.Count) {
                $revisar += "Fora da lista aprovada ($($naoAprovadas.Count)): $(($naoAprovadas | Select-Object -First 15 | ForEach-Object { $_.Nome }) -join ', ')."
            }
        }

        $status = if ($problemas.Count) { 'FALHA' } elseif ($revisar.Count) { 'REVISAR' } else { 'OK' }
        New-Resultado -Status $status -Valor ($estados -join '; ') -Detalhes ((@($problemas) + @($revisar)) -join ' ')
    }
    Aplicar  = {
        param($Cfg)
        foreach ($nome in $Cfg.RecursosDesabilitar) {
            $recurso = $null
            try { $recurso = Get-WindowsOptionalFeature -Online -FeatureName $nome -ErrorAction SilentlyContinue } catch { $recurso = $null }
            if ($recurso -and "$($recurso.State)" -in @('Enabled', 'EnablePending')) {
                Disable-WindowsOptionalFeature -Online -FeatureName $nome -NoRestart | Out-Null
            }
        }
    }
}
