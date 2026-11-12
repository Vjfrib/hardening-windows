"""Verificações estáticas sem PowerShell (só Python 3, biblioteca padrão).

Rodar na raiz do repositório:  python3 tests/test_static.py -v
"""
import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONTROLES = ROOT / "scripts" / "controles"

ARQUIVOS = {
    "01": "01-SenhaMinima.ps1",
    "02": "02-ComplexidadeSenha.ps1",
    "03": "03-HistoricoSenhas.ps1",
    "04": "04-ValidadeSenha.ps1",
    "05": "05-LimiteTentativas.ps1",
    "06": "06-DuracaoBloqueio.ps1",
    "07": "07-RenomearAdministrador.ps1",
    "08": "08-DesabilitarConvidado.ps1",
    "09": "09-UAC.ps1",
    "10": "10-LogonRedeContasLocais.ps1",
    "11": "11-AuditoriaLogon.ps1",
    "12": "12-FirewallEPortas.ps1",
    "13": "13-ProtecaoLogs.ps1",
    "14": "14-UsuariosEGrupos.ps1",
    "15": "15-AplicacoesERecursos.ps1",
    "16": "16-ServicosEContasServico.ps1",
}
SOMENTE_AUDITORIA = {"10", "12", "13", "16"}

# Trechos de código mostrados nos slides 08 a 13 (arquivo:linha), conferidos linha a linha.
SLIDES = [
    ("01-SenhaMinima.ps1", 31, [
        "$target = [int]$Context.Config.Password.MinimumPasswordLength",
        "if ($PSCmdlet.ShouldProcess('Política de senha local', \"MinimumPasswordLength=$target\")) {",
        "Set-HWSecurityValues -Context $Context -Values @{ MinimumPasswordLength = $target }",
    ]),
    ("07-RenomearAdministrador.ps1", 79, [
        "if ($PSCmdlet.ShouldProcess($current.Observed.SID, 'Renomear a conta interna Administrador')) {",
        "Rename-LocalUser -SID $current.Observed.SID -NewName $desired -ErrorAction Stop",
    ]),
    ("11-AuditoriaLogon.ps1", 68, [
        "$guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'",
        "if ($PSCmdlet.ShouldProcess('Auditoria da subcategoria Logon', 'Habilitar sucesso e falha')) {",
        "Set-HWAuditPolicy -Context $Context -Guid $guid -Value 3",
    ]),
    ("12-FirewallEPortas.ps1", 6, [
        "$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |",
        "Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)",
        "$tcp = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |",
    ]),
    ("13-ProtecaoLogs.ps1", 8, [
        "$acl = Get-Acl -LiteralPath $logsPath -ErrorAction Stop",
        "$channels = @(Get-WinEvent -ListLog @('Security','System') -ErrorAction Stop |",
        "Select-Object LogName, IsEnabled, MaximumSizeInBytes, LogMode, SecurityDescriptor)",
    ]),
    ("15-AplicacoesERecursos.ps1", 81, [
        "$result = Disable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart -ErrorAction Stop",
        "$changed = $true",
        "if ($result.RestartNeeded) { $restart = $true }",
    ]),
]

# Cmdlets e programas que mudam estado; não podem aparecer nos controles somente auditoria.
MUDANCAS = re.compile(
    r"\b(Set-|Rename-|Disable-|Enable-|Remove-|New-ItemProperty|Stop-Service|Set-Service|"
    r"Set-NetFirewall|New-NetFirewallRule|Set-Acl|Limit-EventLog|wevtutil|secedit\.exe\s+/configure|auditpol\.exe\s+/set)",
    re.IGNORECASE,
)


def ler(caminho: pathlib.Path) -> str:
    return caminho.read_text(encoding="utf-8-sig")


def sem_comentarios(texto: str) -> str:
    texto = re.sub(r"<#.*?#>", "", texto, flags=re.S)
    return "\n".join(l.split("#", 1)[0] if not l.strip().startswith("#") else "" for l in texto.splitlines())


class Estrutura(unittest.TestCase):
    def test_arquivos_principais(self):
        for rel in [
            "Main.ps1", "README.md", "PSScriptAnalyzerSettings.psd1", ".gitattributes",
            "scripts/lib/Common.psm1", "scripts/lib/Safety.psm1", "scripts/lib/Backup.psm1", "scripts/lib/Reporting.psm1",
            "scripts/config/perfil-academico.example.json", "scripts/config/aprovacoes.example.json",
            "tests/Test-Static.ps1", "tests/Test-Contracts.ps1", "tests/Invoke-CicloLaboratorio.ps1",
            "docs/matriz-controles.md", "docs/plano-de-testes.md", "docs/riscos-e-limitacoes.md", "docs/handoff-riscos-e-ataques.md",
            "docs/Relatorio_Tecnico_Hardening_Windows_Grupo2.pdf",
            "apresentacao/Apresentacao_Hardening_Windows_Grupo2.pdf", "apresentacao/roteiro-de-fala.md",
            "referencias/checklist-creditos.md", ".github/workflows/ci.yml",
        ]:
            self.assertTrue((ROOT / rel).is_file(), rel)

    def test_exatamente_16_controles(self):
        encontrados = sorted(p.name for p in CONTROLES.glob("*.ps1"))
        self.assertEqual(encontrados, sorted(ARQUIVOS.values()))

    def test_catalogo_bate_com_arquivos(self):
        common = ler(ROOT / "scripts/lib/Common.psm1")
        for cid, arquivo in ARQUIVOS.items():
            tipo = "SomenteAuditoria" if cid in SOMENTE_AUDITORIA else "Aplicavel"
            padrao = rf"Id = '{cid}';.*Arquivo = '{re.escape(arquivo)}'; Tipo = '{tipo}'"
            self.assertRegex(common, padrao, cid)


class Codificacao(unittest.TestCase):
    def test_bom_utf8_em_todos_os_scripts(self):
        arquivos = [p for ext in ("*.ps1", "*.psm1", "*.psd1") for p in ROOT.rglob(ext) if ".git" not in p.parts]
        self.assertGreater(len(arquivos), 20)
        for p in arquivos:
            self.assertTrue(p.read_bytes().startswith(b"\xef\xbb\xbf"), f"{p.relative_to(ROOT)} sem BOM")

    def test_sem_tabulacao(self):
        for p in [*ROOT.rglob("*.ps1"), *ROOT.rglob("*.psm1")]:
            if ".git" in p.parts:
                continue
            self.assertNotIn("\t", ler(p), str(p.relative_to(ROOT)))


class Controles(unittest.TestCase):
    def test_funcoes_por_controle(self):
        for cid, arquivo in ARQUIVOS.items():
            texto = ler(CONTROLES / arquivo)
            self.assertIn(f"function Get-HWControl{cid} ", texto)
            self.assertIn(f"function Test-HWControl{cid} ", texto)
            tem_set = f"function Set-HWControl{cid} " in texto
            tem_restore = f"function Restore-HWControl{cid} " in texto
            if cid in SOMENTE_AUDITORIA:
                self.assertFalse(tem_set or tem_restore, f"{cid} é somente auditoria")
            else:
                self.assertTrue(tem_set and tem_restore, f"{cid} precisa de Set e Restore")

    def test_set_usa_shouldprocess(self):
        for cid, arquivo in ARQUIVOS.items():
            if cid in SOMENTE_AUDITORIA:
                continue
            texto = ler(CONTROLES / arquivo)
            for nome in (f"Set-HWControl{cid}", f"Restore-HWControl{cid}"):
                corpo = texto.split(f"function {nome} ", 1)[1].split("\nfunction ", 1)[0]
                self.assertIn("SupportsShouldProcess", corpo, nome)
                self.assertIn("$PSCmdlet.ShouldProcess(", corpo, nome)

    def test_somente_auditoria_nao_altera(self):
        for cid in sorted(SOMENTE_AUDITORIA):
            codigo = sem_comentarios(ler(CONTROLES / ARQUIVOS[cid]))
            achados = [m.group(0) for m in MUDANCAS.finditer(codigo)]
            self.assertEqual(achados, [], f"controle {cid} chama {achados}")

    def test_linhas_citadas_nos_slides(self):
        for arquivo, linha, esperado in SLIDES:
            linhas = ler(CONTROLES / arquivo).splitlines()
            trecho = [l.strip() for l in linhas[linha - 1: linha - 1 + len(esperado)]]
            self.assertEqual(trecho, esperado, f"{arquivo}:{linha}")


class Configuracao(unittest.TestCase):
    def test_perfil_segue_checklist(self):
        perfil = json.loads((ROOT / "scripts/config/perfil-academico.example.json").read_text(encoding="utf-8"))
        p = perfil["Password"]
        self.assertGreaterEqual(p["MinimumPasswordLength"], 12)
        self.assertEqual(p["PasswordComplexity"], 1)
        self.assertGreaterEqual(p["PasswordHistorySize"], 5)
        self.assertLessEqual(p["MaximumPasswordAge"], 90)
        self.assertTrue(1 <= p["LockoutBadCount"] <= 5)
        self.assertGreaterEqual(p["LockoutDuration"], 15)
        self.assertLessEqual(p["ResetLockoutCount"], p["LockoutDuration"])

    def test_aprovacao_exemplo_nao_autoriza_nada(self):
        ap = json.loads((ROOT / "scripts/config/aprovacoes.example.json").read_text(encoding="utf-8"))
        for campo in ("AmbienteDeLaboratorio", "SnapshotConfirmado", "ContaDeRecuperacaoConfirmada", "PermitirMaquinaFisica"):
            self.assertIs(ap[campo], False, campo)
        self.assertEqual(ap["ControlesAprovados"], [])

    def test_aprovacao_real_nao_versionada(self):
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("scripts/config/aprovacoes.json", gitignore)
        self.assertIn("!scripts/lib/", gitignore)


class Documentacao(unittest.TestCase):
    def test_imagens_e_links_do_readme_existem(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        alvos = re.findall(r"\]\(([^)#\s]+)\)", readme) + re.findall(r'src="([^"]+)"', readme)
        locais = [a for a in alvos if not a.startswith(("http://", "https://", "mailto:"))]
        self.assertGreater(len(locais), 15)
        for alvo in locais:
            self.assertTrue((ROOT / alvo).exists(), alvo)

    def test_readme_mostra_todos_os_slides(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        slides = sorted((ROOT / "docs/slides").glob("slide-*.png"))
        self.assertEqual(len(slides), 15)
        for s in slides:
            self.assertIn(f"docs/slides/{s.name}", readme)


if __name__ == "__main__":
    unittest.main()
