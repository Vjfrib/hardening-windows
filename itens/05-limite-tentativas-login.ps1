# Item 5 - Limite de tentativas de login (checklist, seção 3.2)
# LockoutBadCount = 0 significa que a conta nunca é bloqueada.
@{
    Id       = 5
    Secao    = '3.2 Bloqueio de conta'
    Nome     = 'Limite de tentativas de login'
    Esperado = { param($Cfg) "Bloqueio após até $($Cfg.Bloqueio.Tentativas) tentativas" }
    Testar   = {
        param($Cfg)
        $atual = [int](Get-ValorDiretiva -Secao 'System Access' -Chave 'LockoutBadCount')
        $texto = if ($atual -eq 0) { 'Nunca bloqueia' } else { "Bloqueia após $atual tentativas" }
        $conforme = ($atual -ge 1) -and ($atual -le $Cfg.Bloqueio.Tentativas)
        New-Resultado -Conforme $conforme -Valor $texto
    }
    Aplicar  = {
        param($Cfg)
        Set-DiretivaSeguranca -Secao 'System Access' -Valores @{ LockoutBadCount = $Cfg.Bloqueio.Tentativas }
    }
}
