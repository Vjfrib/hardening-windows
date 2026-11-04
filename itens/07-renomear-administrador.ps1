# Item 7 - Renomear a conta Administrador padrão (checklist, seção 3.3)
# A conta é achada pelo SID (termina em 500), não pelo nome.
@{
    Id       = 7
    Secao    = '3.3 Contas privilegiadas'
    Nome     = 'Renomear o Administrador padrão'
    Esperado = { param($Cfg) 'Nome não óbvio' }
    Testar   = {
        param($Cfg)
        $conta = Get-ContaLocalPorRid -Rid 500
        if (-not $conta) {
            return New-Resultado -Status 'REVISAR' -Valor 'Não encontrada' -Detalhes 'Conta com SID terminado em 500 não encontrada (máquina de domínio?).'
        }
        $obvio = $Cfg.NomesObviosAdministrador -contains $conta.Name
        $situacao = if ($conta.Enabled) { 'habilitada' } else { 'desabilitada' }
        New-Resultado -Conforme (-not $obvio) -Valor $conta.Name -Detalhes "SID $($conta.SID), conta $situacao."
    }
    Aplicar  = {
        param($Cfg)
        $novo = $Cfg.NovoNomeAdministrador
        if ([string]::IsNullOrWhiteSpace($novo)) {
            throw 'Defina NovoNomeAdministrador em config\hardening.config.psd1 (nome combinado com a ATI-PE).'
        }
        if ($Cfg.NomesObviosAdministrador -contains $novo) {
            throw "O nome '$novo' está na lista de nomes óbvios."
        }
        $conta = Get-ContaLocalPorRid -Rid 500
        Rename-LocalUser -SID $conta.SID -NewName $novo
    }
}
