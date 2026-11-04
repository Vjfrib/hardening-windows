# Item 14 - Proteger a criação de usuários e grupos (checklist, seção 3.6)
#   (1) Direitos sensíveis só para Administradores: assumir a propriedade de arquivos,
#       fazer backup, restaurar arquivos e depurar programas.
#   (2) Auditoria de Gerenciamento de Contas de Usuário e de Grupos de Segurança
#       (eventos 4720 conta criada, 4732 membro adicionado a grupo local, 4740 conta bloqueada).
#   Evidência: membros atuais do grupo Administradores.
@{
    Id       = 14
    Secao    = '3.6 Lacunas apontadas pela ATI-PE'
    Nome     = 'Proteger a criação de usuários e grupos'
    Esperado = { param($Cfg) 'Direitos sensíveis só para Administradores; auditoria de contas e grupos' }
    Testar   = {
        param($Cfg)
        $direitos = [ordered]@{
            SeTakeOwnershipPrivilege = 'Assumir a propriedade'
            SeBackupPrivilege        = 'Fazer backup'
            SeRestorePrivilege       = 'Restaurar arquivos'
            SeDebugPrivilege         = 'Depurar programas'
        }
        $problemas = @()
        foreach ($direito in $direitos.Keys) {
            $contas = Get-DireitoUsuario -Direito $direito
            $extras = @($contas | Where-Object { $_ -ne $script:SID.Administradores })
            if ($extras.Count) { $problemas += "$($direitos[$direito]) ($direito) também com: $(Format-ListaContas $extras)." }
        }

        $usuarios = Get-ValorAuditoria -Guid $script:Subcategoria.GerenciamentoDeContaUsuario
        $grupos = Get-ValorAuditoria -Guid $script:Subcategoria.GerenciamentoDeGrupoSeguranca
        if ($usuarios -ne 3) { $problemas += "Auditoria de contas de usuário em '$(Format-ValorAuditoria $usuarios)'." }
        if ($grupos -ne 3) { $problemas += "Auditoria de grupos de segurança em '$(Format-ValorAuditoria $grupos)'." }

        try {
            $admins = @(Get-LocalGroupMember -SID $script:SID.Administradores | ForEach-Object { "$($_.Name) ($($_.ObjectClass))" })
        } catch {
            $admins = @("Não foi possível listar: $($_.Exception.Message)")
        }
        Save-Evidencia -Nome 'item14-membros-administradores.txt' -Dados $admins

        $valor = "Auditoria de contas: $(Format-ValorAuditoria $usuarios); grupos: $(Format-ValorAuditoria $grupos)"
        $detalhes = (@($problemas) + @("Membros de Administradores: $($admins -join ', ').")) -join ' '
        New-Resultado -Conforme ($problemas.Count -eq 0) -Valor $valor -Detalhes $detalhes
    }
    Aplicar  = {
        param($Cfg)
        foreach ($direito in @('SeTakeOwnershipPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeDebugPrivilege')) {
            Set-DireitoUsuario -Direito $direito -Contas @($script:SID.Administradores)
        }
        Enable-Auditoria -Guid $script:Subcategoria.GerenciamentoDeContaUsuario -Sucesso -Falha
        Enable-Auditoria -Guid $script:Subcategoria.GerenciamentoDeGrupoSeguranca -Sucesso -Falha
    }
}
