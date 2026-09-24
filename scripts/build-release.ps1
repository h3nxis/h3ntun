param(
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"
$ProjectDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $OutputPath) {
    $Version = (Get-Content -LiteralPath (Join-Path $ProjectDir "VERSION") -Raw).Trim()
    $OutputPath = Join-Path (Split-Path $ProjectDir -Parent) "h3ntun-$Version.zip"
}
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$StagingDir = Join-Path ([System.IO.Path]::GetTempPath()) ("h3ntun-release-" + [guid]::NewGuid().ToString("N"))
$BundleDir = Join-Path $StagingDir "h3ntun"

try {
    New-Item -ItemType Directory -Path $BundleDir | Out-Null
    foreach ($Directory in @(".github", "h3ntun", "config", "scripts", "systemd", "tests")) {
        Copy-Item -Recurse -Path (Join-Path $ProjectDir $Directory) -Destination $BundleDir
    }
    foreach ($File in @(".gitattributes", ".gitignore", "CHANGELOG.md", "LICENSE", "pyproject.toml", "README.md", "README_FA.md", "RELEASE_NOTES_0.4.0.md", "SECURITY.md", "TEST_REPORT.md", "TEST_REPORT_USER_CHANGES_FA.md", "LAB_REPORT_FA.md", "LAB_REPORT.json", "VERSION")) {
        Copy-Item -Path (Join-Path $ProjectDir $File) -Destination $BundleDir
    }
    Get-ChildItem -Path $BundleDir -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force
    if (Test-Path -LiteralPath $OutputPath) {
        Remove-Item -LiteralPath $OutputPath -Force
    }
    Compress-Archive -Path $BundleDir -DestinationPath $OutputPath -CompressionLevel Optimal
    $Hash = Get-FileHash -Algorithm SHA256 -LiteralPath $OutputPath
    [pscustomobject]@{
        Archive = $OutputPath
        SHA256 = $Hash.Hash.ToLowerInvariant()
    } | Format-List
}
finally {
    if (Test-Path -LiteralPath $StagingDir) {
        Remove-Item -LiteralPath $StagingDir -Recurse -Force
    }
}
