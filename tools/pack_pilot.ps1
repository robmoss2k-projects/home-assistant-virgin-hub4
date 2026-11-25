# Build a local-only pilot ZIP from runtime files, independent of Git/GitHub.
# Requires PowerShell 7. Writes only to the repository's ignored dist directory.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$component = 'custom_components/virgin_hub4'

function Assert-LocalPath([string] $LiteralPath) {
    if ((Get-Item -LiteralPath $LiteralPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Refusing redirected path: $LiteralPath"
    }
}

foreach ($directory in @('custom_components', $component, "$component/brand", "$component/translations")) {
    Assert-LocalPath (Join-Path $root $directory)
}
$manifestPath = Join-Path $root "$component/manifest.json"
Assert-LocalPath $manifestPath
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.domain -cne 'virgin_hub4' -or $manifest.version -notmatch '^\d+\.\d+\.\d+$') {
    throw 'Unexpected pilot integration domain or version'
}

[string[]] $members = @('LICENSE', "$component/manifest.json", "$component/services.yaml", "$component/translations/en.json")
$members += @(Get-ChildItem -LiteralPath (Join-Path $root $component) -File -Filter '*.py' |
    Where-Object { $_.Name -cmatch '^[a-z_][a-z_0-9]*\.py$' } |
    ForEach-Object { "$component/$($_.Name)" })
$members += @('icon.png', 'icon@2x.png', 'logo.png', 'logo@2x.png', 'dark_logo.png', 'dark_logo@2x.png' |
    ForEach-Object { "$component/brand/$_" })
foreach ($required in @('__init__.py', 'config_flow.py')) {
    if ("$component/$required" -cnotin $members) { throw "Missing integration file: $required" }
}
[Array]::Sort($members, [StringComparer]::Ordinal)

$buffer = [IO.MemoryStream]::new()
try {
    $archive = [IO.Compression.ZipArchive]::new($buffer, [IO.Compression.ZipArchiveMode]::Create, $true)
    try {
        foreach ($member in $members) {
            $source = Join-Path $root $member
            Assert-LocalPath $source
            $entry = $archive.CreateEntry($member, [IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = [DateTimeOffset]::new(2000, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
            $entry.ExternalAttributes = 0
            $inputStream = [IO.File]::OpenRead($source)
            try {
                $entryStream = $entry.Open()
                try { $inputStream.CopyTo($entryStream) }
                finally { $entryStream.Dispose() }
            }
            finally { $inputStream.Dispose() }
        }
    }
    finally { $archive.Dispose() }
    $bytes = $buffer.ToArray()
}
finally { $buffer.Dispose() }

$digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
$dist = Join-Path $root 'dist'
if (!(Test-Path -LiteralPath $dist)) { New-Item -ItemType Directory -Path $dist | Out-Null }
Assert-LocalPath $dist
$path = Join-Path $dist "virgin_hub4-$($manifest.version)-private-pilot-$($digest.Substring(0, 12)).zip"
if (Test-Path -LiteralPath $path) {
    Assert-LocalPath $path
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $digest) {
        throw "Existing pilot archive does not match the expected digest: $path"
    }
}
else {
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew)
    try { $stream.Write($bytes, 0, $bytes.Length) }
    finally { $stream.Dispose() }
}

[pscustomobject]@{ Archive = $path; SHA256 = $digest; Files = $members.Count }
