Execute `./tests/Test-Static.ps1` para conferir os 16 arquivos e validar a sintaxe em PowerShell. A verificação `python tests/verify_package.py` também confere os modelos JSON.

Execute `./tests/Test-Modes.ps1` em PowerShell de 64 bits para testar a demonstração, a reabertura do relatório e a rejeição de mutações em modo de demonstração. O teste de `Apply -WhatIf` usa um controle simulado, com um marcador que acusa qualquer chamada ao setter. Os testes criam somente arquivos temporários. Os efeitos das políticas exigem os ensaios em VM descritos no plano de testes.
