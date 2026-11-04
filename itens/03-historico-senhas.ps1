# Item 3 - Histórico de senhas (checklist, seção 3.1)
@{
    Id       = 3
    Secao    = '3.1 Política de senha'
    Nome     = 'Histórico de senhas'
    Esperado = { param($Cfg) "Lembrar as últimas $($Cfg.Senha.Historico) ou mais" }
    Testar   = {
        param($Cfg)
        $atual = [int](Get-ValorDiretiva -Secao 'System Access' -Chave 'PasswordHistorySize')
        New-Resultado -Conforme ($atual -ge $Cfg.Senha.Historico) -Valor "$atual senhas lembradas"
    }
    Aplicar  = {
        param($Cfg)
        Set-DiretivaSeguranca -Secao 'System Access' -Valores @{ PasswordHistorySize = $Cfg.Senha.Historico }
    }
}
