# Item 9 - UAC com nível de notificação elevado (checklist, seção 3.4)
#   EnableLUA = 1                   modo de aprovação do administrador ligado
#   FilterAdministratorToken = 1    vale também para o Administrador padrão
#   ConsentPromptBehaviorAdmin = 2  pedir consentimento na área de trabalho segura
#                                   (1 = pedir credenciais na área segura, também aceito)
#   PromptOnSecureDesktop = 1       usar a área de trabalho segura
@{
    Id       = 9
    Secao    = '3.4 Controle de privilégios e acesso'
    Nome     = 'UAC com nível de notificação elevado'
    Esperado = { param($Cfg) 'Consentimento na área de trabalho segura' }
    Testar   = {
        param($Cfg)
        $caminho = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $aceitos = [ordered]@{
            EnableLUA                  = @(1)
            FilterAdministratorToken   = @(1)
            ConsentPromptBehaviorAdmin = @(1, 2)
            PromptOnSecureDesktop      = @(1)
        }
        $partes = @()
        $erradas = @()
        foreach ($nome in $aceitos.Keys) {
            $valor = Get-ValorRegistro -Caminho $caminho -Nome $nome
            $texto = if ($null -eq $valor) { 'ausente' } else { "$valor" }
            $partes += "$nome=$texto"
            if ($aceitos[$nome] -notcontains $valor) { $erradas += $nome }
        }
        $detalhes = if ($erradas) { "Fora do esperado: $($erradas -join ', ')." } else { '' }
        New-Resultado -Conforme ($erradas.Count -eq 0) -Valor ($partes -join '; ') -Detalhes $detalhes
    }
    Aplicar  = {
        param($Cfg)
        $caminho = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Set-ValorRegistro -Caminho $caminho -Nome 'EnableLUA' -Valor 1
        Set-ValorRegistro -Caminho $caminho -Nome 'FilterAdministratorToken' -Valor 1
        Set-ValorRegistro -Caminho $caminho -Nome 'PromptOnSecureDesktop' -Valor 1
        if ((Get-ValorRegistro -Caminho $caminho -Nome 'ConsentPromptBehaviorAdmin') -notin @(1, 2)) {
            Set-ValorRegistro -Caminho $caminho -Nome 'ConsentPromptBehaviorAdmin' -Valor 2
        }
    }
}
