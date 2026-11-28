# Keywarden installer for Windows (x86_64), PowerShell 5.1 or newer:
#   irm https://onokashino.github.io/keywarden/install.ps1 | iex
# Downloads the release archive from GitHub, checks it against SHA256SUMS and installs
# into %LOCALAPPDATA%\Programs\Keywarden without administrator rights.
# When a release signing key is set below, SHA256SUMS must also carry a valid signature
# (SHA256SUMS.sig, checked with ssh-keygen); $env:KEYWARDEN_UNSIGNED=1 skips that for old releases.
# Run it again any time: with Keywarden already installed it checks the installation and
# offers to fix what is broken, update, or pick the optional parts.
# $env:KEYWARDEN_PARTS picks them without questions, space separated: browser ssh.
# $env:KEYWARDEN_YES=1: no questions, install or update.
# A specific version: $env:KEYWARDEN_VERSION='v0.2.10'. $env:KEYWARDEN_NO_LAUNCH=1: do not open the app.
# Everything is inside a function so a download cut off halfway runs nothing.

function Install-Keywarden {
  $ErrorActionPreference = 'Stop'
  $ProgressPreference = 'SilentlyContinue'
  $repo = 'onokashino/keywarden'
  $base = if ($env:KEYWARDEN_MIRROR) { $env:KEYWARDEN_MIRROR } else { "https://github.com/$repo/releases/download" }
  $amo = 'https://addons.mozilla.org/firefox/addon/keywarden/'
  # public half of the release signing key (packaging/release-key.pub); empty: checksum only
  $signer = ''
  $onWindows = $env:OS -eq 'Windows_NT'
  $dir = if ($env:KEYWARDEN_DIR) { $env:KEYWARDEN_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\Keywarden' }

  function Ok($m) { Write-Host "  + $m" -ForegroundColor Green }
  function Warn($m) { Write-Host "  ! $m" -ForegroundColor Yellow }
  function Bad($m) { Write-Host "  x $m" -ForegroundColor Yellow }
  $names = 'keywardend', 'kw', 'keywarden-ui', 'keywarden-host'
  $kw = Join-Path $dir 'kw.exe'
  $lnk = if ($onWindows) { Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Keywarden.lnk' }
  function Fix($what) {
    switch ($what) {
      'browser' {
        $global:LASTEXITCODE = 1
        try { & $kw browser-setup *> $null } catch { }
        if ($LASTEXITCODE -eq 0) { Ok 'browsers can reach Keywarden' } else { Warn 'browser host not registered, run: kw browser-setup' }
      }
      'ssh' {
        $global:LASTEXITCODE = 1
        try { & $kw ssh-setup *> $null } catch { }
        if ($LASTEXITCODE -eq 0) { Ok 'SSH agent for all programs (after the next sign-in; undo: kw ssh-setup --off)' } else { Warn 'SSH agent not connected, run: kw ssh-setup' }
      }
      'path' {
        $path = [Environment]::GetEnvironmentVariable('Path', 'User')
        [Environment]::SetEnvironmentVariable('Path', (("$path".TrimEnd(';') + ';' + $dir).TrimStart(';')), 'User')
        Ok 'added to PATH (new terminals will see kw)'
      }
      'shortcut' {
        $sc = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
        $sc.TargetPath = Join-Path $dir 'keywarden-ui.exe'
        $sc.WorkingDirectory = $dir
        $sc.Save()
        Ok 'shortcut in the Start menu'
      }
    }
  }
  function Agree($question, $default) {
    $hint = if ($default) { 'Y/n' } else { 'y/N' }
    $a = Read-Host "  $question [$hint]"
    if (-not $a) { return $default }
    return $a -like 'y*'
  }
  function Choose-Parts {
    $p = @()
    if (Agree 'Browser link, so the extension can reach Keywarden?' $true) { $p += 'browser' }
    if (Agree 'SSH agent for all programs (ssh, git and IDEs see the keys in your vault)?' $false) { $p += 'ssh' }
    return ($p -join ' ')
  }
  function Fetch($url, $out) {
    if (-not $env:KEYWARDEN_MIRROR -and $url -notlike 'https://*') { throw "refusing a non-https download: $url" }
    Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
  }

  Write-Host "`n  Keywarden installer`n"
  if ($onWindows -and $env:PROCESSOR_ARCHITECTURE -notin 'AMD64', 'ARM64') {
    throw "no ready build for $($env:PROCESSOR_ARCHITECTURE). Build from source: https://onokashino.github.io/keywarden/docs/#install"
  }
  # Windows PowerShell 5.1 may still default to TLS 1.0
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

  $tag = $env:KEYWARDEN_VERSION
  if (-not $tag) {
    # /releases/latest redirects to /releases/tag/vX.Y.Z; no API call, no rate limit
    $req = [Net.WebRequest]::Create("https://github.com/$repo/releases/latest")
    $req.Method = 'HEAD'
    $req.AllowAutoRedirect = $false
    $res = $req.GetResponse()
    $tag = ($res.Headers['Location'] -split '/')[-1]
    $res.Close()
  }
  if ($tag -notmatch '^v[0-9][0-9A-Za-z.\-]*$') { throw "no published release yet: https://github.com/$repo/releases" }

  $parts = if ($null -ne $env:KEYWARDEN_PARTS) { $env:KEYWARDEN_PARTS } else { 'browser' }
  $talk = -not $env:KEYWARDEN_YES -and [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
  $have = $null
  if (Test-Path $kw) { $have = ((& $kw --version 2>$null) -split ' ')[-1] }
  if ($have) {
    # what is wrong with the installation: files, browser, path, shortcut
    $problems = @()
    if ("v$have" -eq $tag) { Ok "Keywarden $have is installed, this is the latest version" } else { Warn "Keywarden $have is installed, the latest is $tag" }
    $miss = $names | Where-Object { -not (Test-Path (Join-Path $dir "$_.exe")) }
    if ($miss) { $problems += 'files'; Bad "missing programs: $($miss -join ', ')" } else { Ok "programs in $dir" }
    # the daemon line is left out: on Windows it starts on demand
    $env:KEYWARDEN_LANG = 'en'
    $fails = @(& $kw browser-setup --check 2>$null | Where-Object { $_ -like 'FAIL*' -and $_ -notlike '*keywardend*' })
    Remove-Item Env:KEYWARDEN_LANG
    if ($fails) { $problems += 'browser'; $fails | ForEach-Object { Bad ("browser link: " + ($_ -replace '^FAIL\s*', '')) } } else { Ok 'browser link' }
    if ($onWindows) {
      if (([Environment]::GetEnvironmentVariable('Path', 'User') -split ';') -notcontains $dir) { $problems += 'path'; Bad 'kw is not in PATH' }
      if (-not (Test-Path $lnk)) { $problems += 'shortcut'; Bad 'no shortcut in the Start menu' }
    }
    if ($talk) {
      $text = @{
        files    = "put the missing programs back (downloads $tag)"
        browser  = 'register the browser link again'
        path     = 'add kw to PATH'
        shortcut = 'put the shortcut back into the Start menu'
      }
      Write-Host "`n  What to do?"
      for ($i = 0; $i -lt $problems.Count; $i++) { Write-Host ("    {0}) {1}" -f ($i + 1), $text[$problems[$i]]) }
      if ($problems.Count -gt 1) { Write-Host '    a) fix all of the above' }
      if ("v$have" -eq $tag) { Write-Host "    r) reinstall $tag" } else { Write-Host "    u) update to $tag" }
      Write-Host '    c) choose the optional parts (browser link, SSH agent)'
      Write-Host '    q) nothing'
      $a = Read-Host '  >'
      $todo = $null
      if ($a -in 'u', 'r') { }
      elseif ($a -eq 'c') { $parts = Choose-Parts }
      elseif ($a -eq 'a') { $todo = $problems }
      elseif ($a -match '^[1-9]$' -and [int]$a -le $problems.Count) { $todo = @($problems[[int]$a - 1]) }
      else { return }
      # missing programs come back only with a full install, which redoes the rest as well
      if ($todo -and $todo -notcontains 'files') {
        $todo | ForEach-Object { Fix $_ }
        Write-Host ''
        return
      }
    }
  }
  elseif ($talk) {
    $a = Read-Host '  Enter installs everything, c lets you choose the parts'
    if ($a -eq 'c') { $parts = Choose-Parts }
  }
  $parts = $parts -split ' '

  $file = "keywarden-$tag-windows-x86_64.zip"
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("keywarden-" + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    Write-Host "  downloading $file"
    try { Fetch "$base/$tag/$file" (Join-Path $tmp $file) } catch { throw "download failed: $base/$tag/$file" }
    try { Fetch "$base/$tag/SHA256SUMS" (Join-Path $tmp 'SHA256SUMS') } catch { throw 'download failed: SHA256SUMS' }
    Ok ("downloaded {0:N1} MB" -f ((Get-Item (Join-Path $tmp $file)).Length / 1MB))

    $want = $null
    foreach ($line in [IO.File]::ReadAllLines((Join-Path $tmp 'SHA256SUMS'))) {
      $cols = $line -split '\s+', 2
      if ($cols.Count -eq 2 -and $cols[1].TrimStart('*') -eq $file) { $want = $cols[0] }
    }
    if (-not $want) { throw "$file is not listed in SHA256SUMS" }
    $got = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $tmp $file)).Hash
    if ($got -ne $want) { throw "checksum mismatch for $file, nothing installed" }
    Ok 'checksum matches SHA256SUMS'

    # the checksum file sits next to the archive, so on its own it only catches a broken download;
    # the signature proves the list was made by the holder of the release key
    if ($signer -and -not $env:KEYWARDEN_UNSIGNED) {
      $keygen = Get-Command ssh-keygen -ErrorAction SilentlyContinue
      if (-not $keygen) { throw 'ssh-keygen is needed to check the release signature (Windows feature: OpenSSH Client)' }
      try { Fetch "$base/$tag/SHA256SUMS.sig" (Join-Path $tmp 'SHA256SUMS.sig') } catch { throw 'this release has no signature (SHA256SUMS.sig), nothing installed' }
      [IO.File]::WriteAllText((Join-Path $tmp 'signers'), "release@keywarden $signer`n")
      # the signed bytes go to stdin untouched: a PowerShell pipe would re-encode them
      $psi = New-Object Diagnostics.ProcessStartInfo
      $psi.FileName = $keygen.Source
      $psi.Arguments = '-Y verify -f "{0}" -I release@keywarden -n keywarden-release -s "{1}"' -f (Join-Path $tmp 'signers'), (Join-Path $tmp 'SHA256SUMS.sig')
      $psi.UseShellExecute = $false
      $psi.RedirectStandardInput = $true
      $psi.RedirectStandardOutput = $true
      $psi.RedirectStandardError = $true
      $p = [Diagnostics.Process]::Start($psi)
      $bytes = [IO.File]::ReadAllBytes((Join-Path $tmp 'SHA256SUMS'))
      $p.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
      $p.StandardInput.Close()
      $null = $p.StandardOutput.ReadToEnd()
      $null = $p.StandardError.ReadToEnd()
      $p.WaitForExit()
      if ($p.ExitCode -ne 0) { throw 'release signature does not match, nothing installed' }
      Ok 'release signature is valid'
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $tmp $file), (Join-Path $tmp 'x'))
    $src = Join-Path (Join-Path $tmp 'x') "keywarden-$tag-windows-x86_64"
    foreach ($n in $names) {
      if (-not (Test-Path (Join-Path $src "$n.exe"))) { throw "the archive has no $n.exe, nothing installed" }
    }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    if ($onWindows) {
      # an update: running programs keep their files locked
      $mine = (Resolve-Path $dir).Path
      Get-Process -Name $names -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and $_.Path.StartsWith($mine, [StringComparison]::OrdinalIgnoreCase) } |
        Stop-Process -Force -ErrorAction SilentlyContinue
      Start-Sleep -Milliseconds 300
    }
    foreach ($n in $names) { Copy-Item (Join-Path $src "$n.exe") (Join-Path $dir "$n.exe") -Force }
    Ok "programs in $dir"
  }
  finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  }

  if ($onWindows) {
    if (([Environment]::GetEnvironmentVariable('Path', 'User') -split ';') -notcontains $dir) { Fix 'path' }
    Fix 'shortcut'
  }
  if ($parts -contains 'browser') { Fix 'browser' } else { Write-Host '  . browser link skipped, later: kw browser-setup' }
  if ($parts -contains 'ssh') { Fix 'ssh' }
  if ($onWindows -and -not $env:KEYWARDEN_NO_LAUNCH) {
    Start-Process (Join-Path $dir 'keywarden-ui.exe')
    Ok 'opening Keywarden'
  }

  Write-Host "`n  Keywarden $tag is installed." -ForegroundColor Green
  Write-Host "  Browser extension: $amo`n"
}

try { Install-Keywarden } catch { Write-Host "  x $($_.Exception.Message)" -ForegroundColor Red }
