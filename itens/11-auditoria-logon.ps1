# Item 11 - Auditoria de logon, sucesso e falha (checklist, seção 3.5)
#   - Subcategoria Logon: sucesso e falha (eventos 4624 e 4625).
#   - Subcategoria Bloqueio de Conta: falha (logon recusado por conta bloqueada).
#     O evento 4740 (conta bloqueada) vem da auditoria de contas do item 14.
#   - Tamanho mínimo do log de Segurança, para caber o volume extra.
@{
    Id       = 11
    Secao    = '3.5 Auditoria'
    Nome     = 'Auditoria de logon'
    Esperado = { param($Cfg) "Sucesso e falha; log de Segurança com $([int]($Cfg.TamanhoMinimoLogSegurancaKB / 1024)) MB ou mais" }
    Testar   = {
        param($Cfg)
        $logon = Get-ValorAuditoria -Guid $script:Subcategoria.Logon
        $bloqueio = Get-ValorAuditoria -Guid $script:Subcategoria.BloqueioDeConta
        $tamanhoKB = [int64]((Get-WinEvent -ListLog Security).MaximumSizeInBytes / 1KB)
        $problemas = @()
        if ($logon -ne 3) { $problemas += "Logon está em '$(Format-ValorAuditoria $logon)'." }
        if (($bloqueio -band 2) -eq 0) { $problemas += 'Bloqueio de conta sem auditoria de falha.' }
        if ($tamanhoKB -lt $Cfg.TamanhoMinimoLogSegurancaKB) { $problemas += "Log de Segurança com $([int]($tamanhoKB / 1024)) MB." }
        $valor = "Logon: $(Format-ValorAuditoria $logon); bloqueio: $(Format-ValorAuditoria $bloqueio); log: $([int]($tamanhoKB / 1024)) MB"
        New-Resultado -Conforme ($problemas.Count -eq 0) -Valor $valor -Detalhes ($problemas -join ' ')
    }
    Aplicar  = {
        param($Cfg)
        Enable-Auditoria -Guid $script:Subcategoria.Logon -Sucesso -Falha
        Enable-Auditoria -Guid $script:Subcategoria.BloqueioDeConta -Falha
        $tamanhoBytes = [int64]$Cfg.TamanhoMinimoLogSegurancaKB * 1KB
        if ((Get-WinEvent -ListLog Security).MaximumSizeInBytes -lt $tamanhoBytes) {
            Invoke-Programa -Programa 'wevtutil.exe' -Argumentos @('sl', 'Security', "/ms:$tamanhoBytes") | Out-Null
        }
    }
}
