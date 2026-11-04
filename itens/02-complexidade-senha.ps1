# Item 2 - Complexidade de senha habilitada (checklist, seção 3.1)
@{
    Id       = 2
    Secao    = '3.1 Política de senha'
    Nome     = 'Complexidade de senha'
    Esperado = { param($Cfg) 'Habilitada' }
    Testar   = {
        param($Cfg)
        $atual = [int](Get-ValorDiretiva -Secao 'System Access' -Chave 'PasswordComplexity')
        $texto = if ($atual -eq 1) { 'Habilitada' } else { 'Desabilitada' }
        New-Resultado -Conforme ($atual -eq 1) -Valor $texto
    }
    Aplicar  = {
        param($Cfg)
        Set-DiretivaSeguranca -Secao 'System Access' -Valores @{ PasswordComplexity = 1 }
    }
}
