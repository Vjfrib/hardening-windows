"""Gera docs/slides/slide-NN.png a partir do PDF da apresentação (para exibir no README).

Uso, na raiz do repositório:  python3 tools/render_slides.py
Requer o pdftoppm (pacote poppler-utils). O PDF não tem o slide 14 (oculto na versão final),
então as imagens seguem a numeração impressa em cada slide.
"""
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
PDF = ROOT / "apresentacao" / "Apresentacao_Hardening_Windows_Grupo2.pdf"
OUT = ROOT / "docs" / "slides"
# Página do PDF -> número impresso no slide (o 14 não está no PDF).
NUMEROS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16]


def main() -> int:
    if not shutil.which("pdftoppm"):
        print("pdftoppm não encontrado (instale poppler-utils).", file=sys.stderr)
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["pdftoppm", "-png", "-r", "96", str(PDF), str(pathlib.Path(tmp) / "p")], check=True)
        paginas = sorted(pathlib.Path(tmp).glob("p-*.png"))
        if len(paginas) != len(NUMEROS):
            print(f"Esperava {len(NUMEROS)} páginas, encontrei {len(paginas)}.", file=sys.stderr)
            return 1
        for pagina, numero in zip(paginas, NUMEROS):
            destino = OUT / f"slide-{numero:02d}.png"
            shutil.copyfile(pagina, destino)
            print(destino.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
