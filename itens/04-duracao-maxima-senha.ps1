# Item 4 - Duração máxima da senha (checklist, seção 3.1)
# No secedit, -1 (ou 0) significa "a senha nunca expira".
@{
    Id       = 4
    Secao    = '3.1 Política de senha'
    Nome     = 'Duração máxima da senha'
    Esperado = { param($Cfg) "Até $($Cfg.Senha.DuracaoMaximaDias) dias" }
    Testar   = {
        param($Cfg)
        $atual = [int](Get-ValorDiretiva -Secao 'System Access' -Chave 'MaximumPasswordAge')
        $nuncaExpira = $atual -le 0
        $texto = if ($nuncaExpira) { 'Nunca expira' } else { "$atual dias" }
        $conforme = (-not $nuncaExpira) -and ($atual -le $Cfg.Senha.DuracaoMaximaDias)
        New-Resultado -Conforme $conforme -Valor $texto
    }
    Aplicar  = {
        param($Cfg)
        Set-DiretivaSeguranca -Secao 'System Access' -Valores @{ MaximumPasswordAge = $Cfg.Senha.DuracaoMaximaDias }
    }
}
