# Testa estrutura e sintaxe sem executar scripts de alteracao.
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$files=@(Get-ChildItem (Join-Path $root 'scripts/controles') -Filter '*.ps1')
if($files.Count -ne 16){throw "Esperados 16 arquivos, encontrados $($files.Count)"}
foreach($i in 1..16){
  $id='{0:D2}' -f $i
  $f=@($files | Where-Object {$_.Name -like "$id-*"})
  if($f.Count -ne 1){throw "Arquivo $id ausente ou duplicado"}
  $content=Get-Content -LiteralPath $f[0].FullName -Raw
  foreach($method in @('Get','Set','Test')){
    if($content -notmatch "function\s+$method-HW${id}State\b"){throw "Contrato do controle $id incompleto ($method)"}
  }
}
$psfiles=@(Get-ChildItem $root -Recurse -File | Where-Object {$_.Extension -in @('.ps1','.psm1')})
foreach($f in $psfiles){
  $tokens=$null; $errors=$null
  [System.Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$tokens,[ref]$errors) | Out-Null
  if($errors.Count -gt 0){throw "Erro PowerShell em $($f.Name): $($errors[0].Message)"}
}
Write-Host "OK: 16 controles com Get/Set/Test; $($psfiles.Count) arquivos sem erros de sintaxe." -ForegroundColor Green
