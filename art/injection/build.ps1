# Intègre les deux SVG en data-URI et produit :
#   - ..\..\ui\injection-anim.js   le module embarqué dans l'exe
#   - animation-logo.html          page autonome, pour montrer ou régler l'animation
#
# `ui/` est copié tel quel dans l'exécutable : rien de ce dossier-ci n'y va,
# seul le fichier généré.
#
# Usage :  powershell -ExecutionPolicy Bypass -File build.ps1
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$ui = Resolve-Path (Join-Path $root '..\..\ui')

function To-DataUri($path) {
  $bytes = [IO.File]::ReadAllBytes($path)
  'data:image/svg+xml;base64,' + [Convert]::ToBase64String($bytes)
}

$logo    = To-DataUri (Join-Path $root 'assets\logo.svg')
$syringe = To-DataUri (Join-Path $root 'assets\syringe.svg')

# 1. Le module, illustrations incorporées : aucun fichier à côté, et la
#    politique de sécurité de contenu de l'app autorise `img-src data:`.
$js = Get-Content (Join-Path $root 'injection-anim.js') -Raw -Encoding UTF8
$js = $js.Replace('assets/logo.svg', $logo).Replace('assets/syringe.svg', $syringe)
$outJs = Join-Path $ui 'injection-anim.js'
Set-Content -Path $outJs -Value $js -Encoding utf8 -NoNewline

# 2. La page de réglage, module compris : un seul fichier à ouvrir ou à envoyer.
$html = Get-Content (Join-Path $root 'index.html') -Raw -Encoding UTF8
$html = $html.Replace('<script src="injection-anim.js"></script>', "<script>`n$js`n</script>")
$outHtml = Join-Path $root 'animation-logo.html'
Set-Content -Path $outHtml -Value $html -Encoding utf8 -NoNewline

"OK -> {0}  ({1:N0} Ko)" -f $outJs, ((Get-Item $outJs).Length / 1KB)
"OK -> {0}  ({1:N0} Ko)" -f $outHtml, ((Get-Item $outHtml).Length / 1KB)
