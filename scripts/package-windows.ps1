[CmdletBinding()]
param(
    [ValidateSet("x86_64-pc-windows-msvc")]
    [string]$Target = "x86_64-pc-windows-msvc",
    [string]$OutputDirectory = "dist",
    [string]$RustToolchain = "1.96.1"
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Package = "sql-connector-windows-x86_64"
$PreviousRustFlags = $env:RUSTFLAGS
$TempRoot = $null

try {
    $StaticCrtFlag = "-C target-feature=+crt-static"
    if ([string]::IsNullOrWhiteSpace($PreviousRustFlags)) {
        $env:RUSTFLAGS = $StaticCrtFlag
    } else {
        $env:RUSTFLAGS = "$PreviousRustFlags $StaticCrtFlag"
    }

    Push-Location $RepoRoot
    try {
        & cargo "+$RustToolchain" build --release --locked --target $Target -p sql-connector
        if ($LASTEXITCODE -ne 0) {
            throw "cargo release build failed"
        }

        $Binary = Join-Path $RepoRoot "target/$Target/release/sql-connector.exe"
        if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
            throw "release binary was not created: $Binary"
        }

        if (-not [IO.Path]::IsPathRooted($OutputDirectory)) {
            $OutputDirectory = Join-Path $RepoRoot $OutputDirectory
        }
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

        $TempRoot = Join-Path ([IO.Path]::GetTempPath()) ("sql-connector-release-" + [guid]::NewGuid().ToString("N"))
        $StagingDirectory = Join-Path $TempRoot $Package
        New-Item -ItemType Directory -Path $StagingDirectory | Out-Null

        Copy-Item -LiteralPath $Binary -Destination (Join-Path $StagingDirectory "sql-connector.exe")
        Copy-Item -LiteralPath "README.md", "SECURITY.md" -Destination $StagingDirectory

        $ManifestLines = & $Binary manifests
        if ($LASTEXITCODE -ne 0) {
            throw "sql-connector manifests failed"
        }
        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        $ManifestPath = Join-Path $StagingDirectory "connectors.json"
        [IO.File]::WriteAllText($ManifestPath, (($ManifestLines -join "`n") + "`n"), $Utf8NoBom)

        $Archive = Join-Path $OutputDirectory "$Package.zip"
        Compress-Archive -Path $StagingDirectory -DestinationPath $Archive -CompressionLevel Optimal -Force
        $Hash = (Get-FileHash $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
        $ChecksumPath = "$Archive.sha256"
        [IO.File]::WriteAllText($ChecksumPath, "$Hash  $Package.zip`n", [Text.Encoding]::ASCII)

        Write-Output $Archive
        Write-Output $ChecksumPath
    } finally {
        Pop-Location
    }
} finally {
    $env:RUSTFLAGS = $PreviousRustFlags
    if ($null -ne $TempRoot -and (Test-Path -LiteralPath $TempRoot)) {
        Remove-Item -LiteralPath $TempRoot -Recurse -Force
    }
}
