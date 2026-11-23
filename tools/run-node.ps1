# Run a script with the ASAR-aware Electron runtime (ELECTRON_RUN_AS_NODE=1).
# usage: .\run-node.ps1 -Script <file.js> [-JsArgs @('a','b')]
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$Script,
  [string[]]$JsArgs = @()
)
$exe = $env:DSH_NODE_EXECUTABLE
if (-not $exe) { Write-Error 'DSH_NODE_EXECUTABLE not set'; exit 2 }
if (-not (Test-Path -LiteralPath $Script)) { Write-Error "no such script: $Script"; exit 2 }

function Quote-Arg([string]$s) {
  if ($s -notmatch '[\s"]') { return $s }
  $escaped = $s -replace '(\\*)"', '$1$1\"'
  return '"' + $escaped + '"'
}

$parts = @((Quote-Arg (Resolve-Path -LiteralPath $Script).Path))
foreach ($a in $JsArgs) { if ($null -ne $a) { $parts += (Quote-Arg ([string]$a)) } }

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $exe
$psi.Arguments = ($parts -join ' ')
$psi.Environment['ELECTRON_RUN_AS_NODE'] = '1'
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
$psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
$p = [System.Diagnostics.Process]::Start($psi)
$errTask = $p.StandardError.ReadToEndAsync()
$out = $p.StandardOutput.ReadToEnd()
$p.WaitForExit()
[Console]::Out.Write($out)
[Console]::Error.Write($errTask.Result)
exit $p.ExitCode
