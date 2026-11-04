# Item 1 - Tamanho mínimo de senha (checklist, seção 3.1)
@{
    Id       = 1
    Secao    = '3.1 Política de senha'
    Nome     = 'Tamanho mínimo de senha'
    Esperado = { param($Cfg) "No mínimo $($Cfg.Senha.TamanhoMinimo) caracteres" }
    Testar   = {
        param($Cfg)
        $atual = [int](Get-ValorDiretiva -Secao 'System Access' -Chave 'MinimumPasswordLength')
        New-Resultado -Conforme ($atual -ge $Cfg.Senha.TamanhoMinimo) -Valor "$atual caracteres"
    }
    Aplicar  = {
        param($Cfg)
        Set-DiretivaSeguranca -Secao 'System Access' -Valores @{ MinimumPasswordLength = $Cfg.Senha.TamanhoMinimo }
    }
}
