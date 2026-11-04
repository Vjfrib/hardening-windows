# Item 8 - Desabilitar a conta Convidado (checklist, seção 3.3)
# A conta é achada pelo SID (termina em 501), não pelo nome.
@{
    Id       = 8
    Secao    = '3.3 Contas privilegiadas'
    Nome     = 'Desabilitar a conta Convidado'
    Esperado = { param($Cfg) 'Desabilitada' }
    Testar   = {
        param($Cfg)
        $conta = Get-ContaLocalPorRid -Rid 501
        if (-not $conta) {
            return New-Resultado -Status 'OK' -Valor 'Não existe'
        }
        $texto = if ($conta.Enabled) { "$($conta.Name): habilitada" } else { "$($conta.Name): desabilitada" }
        New-Resultado -Conforme (-not $conta.Enabled) -Valor $texto
    }
    Aplicar  = {
        param($Cfg)
        $conta = Get-ContaLocalPorRid -Rid 501
        Disable-LocalUser -SID $conta.SID
    }
}
