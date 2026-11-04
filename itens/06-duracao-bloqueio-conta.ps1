# Item 6 - Duração do bloqueio de conta (checklist, seção 3.2)
# O Windows só guarda a duração quando o limite de tentativas (item 5) está ativo.
# LockoutDuration = -1 significa "até um administrador desbloquear".
@{
    Id       = 6
    Secao    = '3.2 Bloqueio de conta'
    Nome     = 'Duração do bloqueio de conta'
    Esperado = { param($Cfg) "$($Cfg.Bloqueio.DuracaoMinutos) min ou mais; contador zerado em até esse tempo" }
    Testar   = {
        param($Cfg)
        $limite = [int](Get-ValorDiretiva -Secao 'System Access' -Chave 'LockoutBadCount')
        if ($limite -eq 0) {
            return New-Resultado -Status 'FALHA' -Valor 'Bloqueio desligado' -Detalhes 'O limite de tentativas (item 5) está desligado, então não há bloqueio.'
        }
        $duracao = [int](Get-ValorDiretiva -Secao 'System Access' -Chave 'LockoutDuration')
        $contador = [int](Get-ValorDiretiva -Secao 'System Access' -Chave 'ResetLockoutCount')
        $textoDuracao = if ($duracao -eq -1) { 'até o administrador desbloquear' } else { "$duracao min" }
        $duracaoOk = ($duracao -eq -1) -or ($duracao -ge $Cfg.Bloqueio.DuracaoMinutos)
        $contadorOk = ($contador -ge 1) -and (($duracao -eq -1) -or ($contador -le $duracao))
        New-Resultado -Conforme ($duracaoOk -and $contadorOk) -Valor "Bloqueio: $textoDuracao; contador zera em $contador min"
    }
    Aplicar  = {
        param($Cfg)
        $valores = @{
            LockoutDuration   = $Cfg.Bloqueio.DuracaoMinutos
            ResetLockoutCount = $Cfg.Bloqueio.ZerarContadorMinutos
        }
        # Sem limite de tentativas a duração não é gravada; liga o item 5 junto.
        if ([int](Get-ValorDiretiva -Secao 'System Access' -Chave 'LockoutBadCount') -eq 0) {
            $valores['LockoutBadCount'] = $Cfg.Bloqueio.Tentativas
        }
        Set-DiretivaSeguranca -Secao 'System Access' -Valores $valores
    }
}
