#
# Valores do checklist "Hardening Windows - Contas e Políticas de Acesso"
# (Gabriel Cortez e Rodrigo Campos). Cada bloco indica o item do checklist.
#
# Ajuste aqui o que for combinado com a ATI-PE. O script lê este arquivo
# tanto no modo Auditar quanto no modo Aplicar.
#
@{
    # ------------------------------------------------------------------
    # 3.1 Política de senha (itens 1 a 4)
    # ------------------------------------------------------------------
    Senha = @{
        TamanhoMinimo     = 12     # Item 1: no mínimo 12 caracteres (CIS sugere 14)
        Complexidade      = $true  # Item 2: exigir complexidade
        Historico         = 5      # Item 3: lembrar as últimas 5 senhas (CIS sugere 24)
        DuracaoMaximaDias = 90     # Item 4: trocar a senha em até 90 dias
    }

    # ------------------------------------------------------------------
    # 3.2 Bloqueio de conta (itens 5 e 6)
    # ------------------------------------------------------------------
    Bloqueio = @{
        Tentativas           = 5   # Item 5: bloquear após 5 tentativas erradas
        DuracaoMinutos       = 15  # Item 6: conta fica bloqueada por 15 minutos
        ZerarContadorMinutos = 15  # Item 6: zera o contador de tentativas após 15 minutos
    }

    # ------------------------------------------------------------------
    # 3.3 Contas privilegiadas (itens 7 e 8)
    # ------------------------------------------------------------------
    # Item 7: novo nome da conta Administrador padrão (SID terminado em 500).
    # Combine o nome com a ATI-PE. Vazio = o script só verifica, não renomeia.
    NovoNomeAdministrador    = ''
    NomesObviosAdministrador = @('Administrator', 'Administrador', 'Admin', 'Root')

    # ------------------------------------------------------------------
    # 3.4 Controle de privilégios e acesso (itens 9 e 10)
    # ------------------------------------------------------------------
    # Item 10: quem entra em "Negar acesso a este computador pela rede".
    #   *S-1-5-113    = Conta local (todas as contas locais)
    #   *S-1-5-114    = Conta local e membro do grupo Administradores (opção mais branda)
    #   *S-1-5-32-546 = Convidados
    # Atenção: com *S-1-5-113, o acesso por RDP com conta local (com NLA) deixa de funcionar.
    ContasNegadasNaRede = @('*S-1-5-113', '*S-1-5-32-546')

    # ------------------------------------------------------------------
    # 3.5 Auditoria (item 11)
    # ------------------------------------------------------------------
    TamanhoMinimoLogSegurancaKB = 196608   # 192 MB, valor sugerido pelo CIS

    # ------------------------------------------------------------------
    # 3.6 Lacunas apontadas pela ATI-PE (itens 12 a 16)
    # ------------------------------------------------------------------
    # Item 12: portas TCP que podem ficar em escuta. Vazio = o script só lista
    # as portas abertas para revisão. Exemplo: @(135, 139, 445, 3389)
    PortasPermitidas        = @()
    IgnorarPortasDinamicas  = $true   # ignora portas 49152 a 65535 (RPC dinâmico)

    # Item 15: recursos opcionais do Windows que devem ficar desativados.
    RecursosDesabilitar = @('SMB1Protocol', 'TelnetClient', 'TFTP')
    # Item 15: aplicações aprovadas (aceita curinga). Vazio = o script só faz o inventário.
    # Exemplo: @('Microsoft Edge*', 'Google Chrome', '7-Zip*')
    AplicacoesAprovadas = @()

    # Item 16: serviços que devem ficar desabilitados. Confirme com a ATI-PE antes.
    ServicosDesabilitar = @('RemoteRegistry', 'SSDPSRV', 'upnphost')
    # Item 16: contas usadas por serviços, que não devem fazer logon interativo
    # nem por Área de Trabalho Remota. Exemplo: @('.\svc_backup', 'DOMINIO\svc_sql')
    ContasDeServico = @()
    # Item 16: contas locais sem logon há mais de N dias entram no relatório.
    DiasSemUsoConta = 90
    # Item 16: $true = o modo Aplicar desabilita essas contas. Por padrão só lista.
    DesabilitarContasSemUso = $false
}
