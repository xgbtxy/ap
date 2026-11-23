# 1-Line Zero-Config Windows Installer for `ap` (agent-primitives)
# Usage:
#   curl.exe -fsSL https://raw.githubusercontent.com/xgbtxy/ap/main/install.ps1 | iex
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo = if ($env:AP_REPO) { $env:AP_REPO } else { "xgbtxy/ap" }
$Version = if ($env:AP_VERSION) { $env:AP_VERSION } else { "latest" }
$BinDir = if ($env:AP_INSTALL_DIR) { $env:AP_INSTALL_DIR } else { Join-Path $HOME ".local\bin" }
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

function Install-ApBinary([string]$SourcePath, [string]$DestPath) {
    $OldPath = "$DestPath.old"
    if (Test-Path $OldPath) {
        Remove-Item -Force -Path $OldPath -ErrorAction SilentlyContinue
    }
    if (Test-Path $DestPath) {
        try {
            Move-Item -Path $DestPath -Destination $OldPath -Force -ErrorAction Stop
        } catch {
            # Fallback if destination cannot be renamed cleanly
        }
    }
    Copy-Item -Path $SourcePath -Destination $DestPath -Force
    if (Test-Path $OldPath) {
        Remove-Item -Force -Path $OldPath -ErrorAction SilentlyContinue
    }
}

$Archive = "ap-x86_64-pc-windows-msvc.zip"
$BaseUrl = if ($Version -eq "latest") {
    "https://github.com/$Repo/releases/latest/download"
} else {
    "https://github.com/$Repo/releases/download/$Version"
}

$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ap_install_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null

try {
    $ZipPath = Join-Path $TmpDir $Archive
    $Downloaded = $false
    Write-Host "[ap install] Downloading native Windows binary ($Archive) ..." -ForegroundColor Cyan
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        & curl.exe -fsSL "$BaseUrl/$Archive" -o $ZipPath 2>$null
        if ($LASTEXITCODE -eq 0 -and (Test-Path $ZipPath)) { $Downloaded = $true }
    }
    if (-not $Downloaded) {
        try {
            Invoke-WebRequest -Uri "$BaseUrl/$Archive" -OutFile $ZipPath -UseBasicParsing
            if (Test-Path $ZipPath) { $Downloaded = $true }
        } catch {}
    }

    if ($Downloaded) {
        $SumsPath = Join-Path $TmpDir "SHA256SUMS"
        $SumsOk = $false
        if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
            & curl.exe -fsSL "$BaseUrl/SHA256SUMS" -o $SumsPath 2>$null
            if ($LASTEXITCODE -eq 0 -and (Test-Path $SumsPath)) { $SumsOk = $true }
        }
        if (-not $SumsOk) {
            try {
                Invoke-WebRequest -Uri "$BaseUrl/SHA256SUMS" -OutFile $SumsPath -UseBasicParsing
                if (Test-Path $SumsPath) { $SumsOk = $true }
            } catch {}
        }
        if (Test-Path $SumsPath) {
            $MatchLine = Get-Content $SumsPath | Where-Object { $_ -match "\s$([regex]::Escape($Archive))$" } | Select-Object -First 1
            if ($MatchLine) {
                $Expected = ($MatchLine -split "\s+")[0].ToLowerInvariant()
                $Actual = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
                if ($Expected -ne $Actual) {
                    throw "SHA-256 checksum mismatch for $Archive (expected $Expected, got $Actual)"
                }
            }
        }
        Expand-Archive -Path $ZipPath -DestinationPath $TmpDir -Force
        Install-ApBinary (Join-Path $TmpDir "ap.exe") (Join-Path $BinDir "ap.exe")
    } elseif (Get-Command cargo -ErrorAction SilentlyContinue) {
        Write-Host "[ap install] Building from Rust source via cargo ..." -ForegroundColor Cyan
        $CargoRoot = Join-Path $TmpDir "cargo"
        & cargo install --git "https://github.com/$Repo.git" --bin ap --locked --root $CargoRoot
        Install-ApBinary (Join-Path $CargoRoot "bin\ap.exe") (Join-Path $BinDir "ap.exe")
    } else {
        throw "Could not download prebuilt binary from $BaseUrl/$Archive and cargo is not installed."
    }

    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($UserPath -notlike "*$BinDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$BinDir;$UserPath", "User")
    }
    if ($env:PATH -notlike "*$BinDir*") {
        $env:PATH = "$BinDir;$env:PATH"
    }

    $ApExe = Join-Path $BinDir "ap.exe"
    if ($env:AP_INIT_ARGS) {
        $SplitArgs = $env:AP_INIT_ARGS -split "\s+"
        & $ApExe init @SplitArgs
    } else {
        & $ApExe init
    }

    Write-Host ""
    Write-Host "----------------------------------------------------------------" -ForegroundColor Green
    Write-Host "[ap] Ready! Your coding agents are now accelerated on Windows." -ForegroundColor Green
    Write-Host "  -> Next step : Open your coding agent and chat normally (0 new commands needed)"
    Write-Host "  -> Check env : ap doctor"
    Write-Host "  -> View gains: ap stats   (see tokens & Windows crashes saved)"
    Write-Host "----------------------------------------------------------------" -ForegroundColor Green
} finally {
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
}
