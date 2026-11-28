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

  # Language: $env:KEYWARDEN_LANG = ru|en, otherwise the Windows display language; "l" in the menu
  # switches it. English text is the key. Russian is written as \u escapes on purpose: Windows
  # PowerShell 5.1 reads a script fetched from the web as Latin-1 and would garble real letters.
  $ru = @{
    'browsers can reach Keywarden' = '\u0431\u0440\u0430\u0443\u0437\u0435\u0440\u044b \u0432\u0438\u0434\u044f\u0442 Keywarden'
    'browser host not registered, run: {0}' = '\u0441\u0432\u044f\u0437\u044c \u0441 \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u043e\u043c \u043d\u0435 \u043d\u0430\u0441\u0442\u0440\u043e\u0435\u043d\u0430, \u0432\u044b\u043f\u043e\u043b\u043d\u0438\u0442\u0435: {0}'
    'SSH agent for all programs (after the next sign-in; undo: {0})' = 'SSH-\u0430\u0433\u0435\u043d\u0442 \u0434\u043b\u044f \u0432\u0441\u0435\u0445 \u043f\u0440\u043e\u0433\u0440\u0430\u043c\u043c (\u043f\u043e\u0441\u043b\u0435 \u0441\u043b\u0435\u0434\u0443\u044e\u0449\u0435\u0433\u043e \u0432\u0445\u043e\u0434\u0430 \u0432 \u0441\u0438\u0441\u0442\u0435\u043c\u0443; \u043e\u0442\u043c\u0435\u043d\u0438\u0442\u044c: {0})'
    'SSH agent not connected, run: {0}' = 'SSH-\u0430\u0433\u0435\u043d\u0442 \u043d\u0435 \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0451\u043d, \u0432\u044b\u043f\u043e\u043b\u043d\u0438\u0442\u0435: {0}'
    'added to PATH (new terminals will see kw)' = '\u0434\u043e\u0431\u0430\u0432\u043b\u0435\u043d\u043e \u0432 PATH (\u043d\u043e\u0432\u044b\u0435 \u0442\u0435\u0440\u043c\u0438\u043d\u0430\u043b\u044b \u0443\u0432\u0438\u0434\u044f\u0442 kw)'
    'shortcut in the Start menu' = '\u044f\u0440\u043b\u044b\u043a \u0432 \u043c\u0435\u043d\u044e \u00ab\u041f\u0443\u0441\u043a\u00bb'
    'Browser link, so the extension can reach Keywarden?' = '\u0421\u0432\u044f\u0437\u044c \u0441 \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u043e\u043c, \u0447\u0442\u043e\u0431\u044b \u0440\u0430\u0441\u0448\u0438\u0440\u0435\u043d\u0438\u0435 \u0432\u0438\u0434\u0435\u043b\u043e Keywarden?'
    'SSH agent for all programs (ssh, git and IDEs see the keys in your vault)?' = 'SSH-\u0430\u0433\u0435\u043d\u0442 \u0434\u043b\u044f \u0432\u0441\u0435\u0445 \u043f\u0440\u043e\u0433\u0440\u0430\u043c\u043c (ssh, git \u0438 IDE \u0432\u0438\u0434\u044f\u0442 \u043a\u043b\u044e\u0447\u0438 \u0438\u0437 \u0431\u0430\u0437\u044b)?'
    'refusing a non-https download: {0}' = '\u0437\u0430\u0433\u0440\u0443\u0437\u043a\u0430 \u043d\u0435 \u043f\u043e https \u043e\u0442\u043a\u043b\u043e\u043d\u0435\u043d\u0430: {0}'
    'Keywarden installer' = 'Keywarden \u00b7 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430'
    'no ready build for {0}. Build from source: {1}' = '\u0433\u043e\u0442\u043e\u0432\u043e\u0439 \u0441\u0431\u043e\u0440\u043a\u0438 \u0434\u043b\u044f {0} \u043d\u0435\u0442. \u0421\u0431\u043e\u0440\u043a\u0430 \u0438\u0437 \u0438\u0441\u0445\u043e\u0434\u043d\u0438\u043a\u043e\u0432: {1}'
    'no published release yet: {0}' = '\u0440\u0435\u043b\u0438\u0437\u043e\u0432 \u043f\u043e\u043a\u0430 \u043d\u0435\u0442: {0}'
    'Keywarden {0} is installed, this is the latest version' = 'Keywarden {0} \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d, \u044d\u0442\u043e \u043f\u043e\u0441\u043b\u0435\u0434\u043d\u044f\u044f \u0432\u0435\u0440\u0441\u0438\u044f'
    'Keywarden {0} is installed, the latest is {1}' = 'Keywarden {0} \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d, \u043f\u043e\u0441\u043b\u0435\u0434\u043d\u044f\u044f \u0432\u0435\u0440\u0441\u0438\u044f {1}'
    'missing programs: {0}' = '\u043d\u0435 \u0445\u0432\u0430\u0442\u0430\u0435\u0442 \u043f\u0440\u043e\u0433\u0440\u0430\u043c\u043c: {0}'
    'programs in {0}' = '\u043f\u0440\u043e\u0433\u0440\u0430\u043c\u043c\u044b \u0432 {0}'
    'browser link: {0}' = '\u0441\u0432\u044f\u0437\u044c \u0441 \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u043e\u043c: {0}'
    'browser link' = '\u0441\u0432\u044f\u0437\u044c \u0441 \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u043e\u043c'
    'kw is not in PATH' = 'kw \u043d\u0435\u0442 \u0432 PATH'
    'no shortcut in the Start menu' = '\u043d\u0435\u0442 \u044f\u0440\u043b\u044b\u043a\u0430 \u0432 \u043c\u0435\u043d\u044e \u00ab\u041f\u0443\u0441\u043a\u00bb'
    'put the missing programs back (downloads {0})' = '\u0432\u0435\u0440\u043d\u0443\u0442\u044c \u043f\u0440\u043e\u043f\u0430\u0432\u0448\u0438\u0435 \u043f\u0440\u043e\u0433\u0440\u0430\u043c\u043c\u044b (\u0441\u043a\u0430\u0447\u0430\u0435\u0442 {0})'
    'register the browser link again' = '\u043d\u0430\u0441\u0442\u0440\u043e\u0438\u0442\u044c \u0441\u0432\u044f\u0437\u044c \u0441 \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u043e\u043c \u0437\u0430\u043d\u043e\u0432\u043e'
    'add kw to PATH' = '\u0434\u043e\u0431\u0430\u0432\u0438\u0442\u044c kw \u0432 PATH'
    'put the shortcut back into the Start menu' = '\u0432\u0435\u0440\u043d\u0443\u0442\u044c \u044f\u0440\u043b\u044b\u043a \u0432 \u043c\u0435\u043d\u044e \u00ab\u041f\u0443\u0441\u043a\u00bb'
    'What to do?' = '\u0427\u0442\u043e \u0441\u0434\u0435\u043b\u0430\u0442\u044c?'
    'fix all of the above' = '\u0438\u0441\u043f\u0440\u0430\u0432\u0438\u0442\u044c \u0432\u0441\u0451 \u043f\u0435\u0440\u0435\u0447\u0438\u0441\u043b\u0435\u043d\u043d\u043e\u0435'
    'reinstall {0}' = '\u043f\u0435\u0440\u0435\u0443\u0441\u0442\u0430\u043d\u043e\u0432\u0438\u0442\u044c {0}'
    'update to {0}' = '\u043e\u0431\u043d\u043e\u0432\u0438\u0442\u044c \u0434\u043e {0}'
    'choose the optional parts (browser link, SSH agent)' = '\u0432\u044b\u0431\u0440\u0430\u0442\u044c \u0434\u043e\u043f\u043e\u043b\u043d\u0438\u0442\u0435\u043b\u044c\u043d\u044b\u0435 \u0447\u0430\u0441\u0442\u0438 (\u0441\u0432\u044f\u0437\u044c \u0441 \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u043e\u043c, SSH-\u0430\u0433\u0435\u043d\u0442)'
    'nothing' = '\u043d\u0438\u0447\u0435\u0433\u043e'
    'Enter installs everything, c lets you choose the parts, l: {0}' = 'Enter \u0441\u0442\u0430\u0432\u0438\u0442 \u0432\u0441\u0451, c \u0434\u0430\u0451\u0442 \u0432\u044b\u0431\u0440\u0430\u0442\u044c \u0447\u0430\u0441\u0442\u0438, l: {0}'
    'downloading {0}' = '\u0437\u0430\u0433\u0440\u0443\u0437\u043a\u0430 {0}'
    'download failed: {0}' = '\u043d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0441\u043a\u0430\u0447\u0430\u0442\u044c: {0}'
    'downloaded {0:N1} MB' = '\u0441\u043a\u0430\u0447\u0430\u043d\u043e {0:N1} \u041c\u0411'
    '{0} is not listed in SHA256SUMS' = '{0} \u043d\u0435\u0442 \u0432 \u0441\u043f\u0438\u0441\u043a\u0435 SHA256SUMS'
    'checksum mismatch for {0}, nothing installed' = '\u043a\u043e\u043d\u0442\u0440\u043e\u043b\u044c\u043d\u0430\u044f \u0441\u0443\u043c\u043c\u0430 {0} \u043d\u0435 \u0441\u043e\u0432\u043f\u0430\u043b\u0430, \u043d\u0438\u0447\u0435\u0433\u043e \u043d\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u043e'
    'checksum matches SHA256SUMS' = '\u043a\u043e\u043d\u0442\u0440\u043e\u043b\u044c\u043d\u0430\u044f \u0441\u0443\u043c\u043c\u0430 \u0441\u043e\u0432\u043f\u0430\u043b\u0430 \u0441 SHA256SUMS'
    'ssh-keygen is needed to check the release signature (Windows feature: OpenSSH Client)' = '\u0434\u043b\u044f \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0438 \u043f\u043e\u0434\u043f\u0438\u0441\u0438 \u0440\u0435\u043b\u0438\u0437\u0430 \u043d\u0443\u0436\u0435\u043d ssh-keygen (\u043a\u043e\u043c\u043f\u043e\u043d\u0435\u043d\u0442 Windows \u00ab\u041a\u043b\u0438\u0435\u043d\u0442 OpenSSH\u00bb)'
    'this release has no signature (SHA256SUMS.sig), nothing installed' = '\u0443 \u044d\u0442\u043e\u0433\u043e \u0440\u0435\u043b\u0438\u0437\u0430 \u043d\u0435\u0442 \u043f\u043e\u0434\u043f\u0438\u0441\u0438 (SHA256SUMS.sig), \u043d\u0438\u0447\u0435\u0433\u043e \u043d\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u043e'
    'release signature does not match, nothing installed' = '\u043f\u043e\u0434\u043f\u0438\u0441\u044c \u0440\u0435\u043b\u0438\u0437\u0430 \u043d\u0435 \u0441\u043e\u0448\u043b\u0430\u0441\u044c, \u043d\u0438\u0447\u0435\u0433\u043e \u043d\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u043e'
    'release signature is valid' = '\u043f\u043e\u0434\u043f\u0438\u0441\u044c \u0440\u0435\u043b\u0438\u0437\u0430 \u0432\u0435\u0440\u043d\u0430'
    'the archive has no {0}, nothing installed' = '\u0432 \u0430\u0440\u0445\u0438\u0432\u0435 \u043d\u0435\u0442 {0}, \u043d\u0438\u0447\u0435\u0433\u043e \u043d\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u043e'
    'browser link skipped, later: {0}' = '\u0441\u0432\u044f\u0437\u044c \u0441 \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u043e\u043c \u043f\u0440\u043e\u043f\u0443\u0449\u0435\u043d\u0430, \u043f\u043e\u0437\u0436\u0435: {0}'
    'opening Keywarden' = '\u043e\u0442\u043a\u0440\u044b\u0432\u0430\u044e Keywarden'
    'Keywarden {0} is installed.' = 'Keywarden {0} \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d.'
    'Browser extension:' = '\u0420\u0430\u0441\u0448\u0438\u0440\u0435\u043d\u0438\u0435 \u0434\u043b\u044f \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0430:'
  }
  $lang = if ($env:KEYWARDEN_LANG) { $env:KEYWARDEN_LANG } elseif ((Get-UICulture).TwoLetterISOLanguageName -eq 'ru') { 'ru' } else { 'en' }
  $other = ''
  function Switch-Lang {
    if ($lang -eq 'ru') { Set-Variable lang 'en' -Scope 1; Set-Variable other ([regex]::Unescape('\u0420\u0443\u0441\u0441\u043a\u0438\u0439')) -Scope 1 }
    else { Set-Variable lang 'ru' -Scope 1; Set-Variable other 'English' -Scope 1 }
  }
  Switch-Lang; Switch-Lang
  function M($en) { if ($lang -eq 'ru' -and $ru.ContainsKey($en)) { [regex]::Unescape($ru[$en]) } else { $en } }
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
        if ($LASTEXITCODE -eq 0) { Ok (M 'browsers can reach Keywarden') } else { Warn ((M 'browser host not registered, run: {0}') -f 'kw browser-setup') }
      }
      'ssh' {
        $global:LASTEXITCODE = 1
        try { & $kw ssh-setup *> $null } catch { }
        if ($LASTEXITCODE -eq 0) { Ok ((M 'SSH agent for all programs (after the next sign-in; undo: {0})') -f 'kw ssh-setup --off') } else { Warn ((M 'SSH agent not connected, run: {0}') -f 'kw ssh-setup') }
      }
      'path' {
        $path = [Environment]::GetEnvironmentVariable('Path', 'User')
        [Environment]::SetEnvironmentVariable('Path', (("$path".TrimEnd(';') + ';' + $dir).TrimStart(';')), 'User')
        Ok (M 'added to PATH (new terminals will see kw)')
      }
      'shortcut' {
        $sc = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
        $sc.TargetPath = Join-Path $dir 'keywarden-ui.exe'
        $sc.WorkingDirectory = $dir
        $sc.Save()
        Ok (M 'shortcut in the Start menu')
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
    if (Agree (M 'Browser link, so the extension can reach Keywarden?') $true) { $p += 'browser' }
    if (Agree (M 'SSH agent for all programs (ssh, git and IDEs see the keys in your vault)?') $false) { $p += 'ssh' }
    return ($p -join ' ')
  }
  function Fetch($url, $out) {
    if (-not $env:KEYWARDEN_MIRROR -and $url -notlike 'https://*') { throw ((M 'refusing a non-https download: {0}') -f $url) }
    Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
  }

  Write-Host ("`n  " + (M 'Keywarden installer') + "`n")
  if ($onWindows -and $env:PROCESSOR_ARCHITECTURE -notin 'AMD64', 'ARM64') {
    throw ((M 'no ready build for {0}. Build from source: {1}') -f $env:PROCESSOR_ARCHITECTURE, 'https://onokashino.github.io/keywarden/docs/#install')
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
  if ($tag -notmatch '^v[0-9][0-9A-Za-z.\-]*$') { throw ((M 'no published release yet: {0}') -f "https://github.com/$repo/releases") }

  $parts = if ($null -ne $env:KEYWARDEN_PARTS) { $env:KEYWARDEN_PARTS } else { 'browser' }
  $talk = -not $env:KEYWARDEN_YES -and [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
  $have = $null
  if (Test-Path $kw) { $have = ((& $kw --version 2>$null) -split ' ')[-1] }
  while ($true) {
  if ($have) {
    # what is wrong with the installation: files, browser, path, shortcut
    $problems = @()
    if ("v$have" -eq $tag) { Ok ((M 'Keywarden {0} is installed, this is the latest version') -f $have) } else { Warn ((M 'Keywarden {0} is installed, the latest is {1}') -f $have, $tag) }
    $miss = $names | Where-Object { -not (Test-Path (Join-Path $dir "$_.exe")) }
    if ($miss) { $problems += 'files'; Bad ((M 'missing programs: {0}') -f ($miss -join ', ')) } else { Ok ((M 'programs in {0}') -f $dir) }
    # the daemon line is left out: on Windows it starts on demand
    $env:KEYWARDEN_LANG = $lang
    $fails = @(& $kw browser-setup --check 2>$null | Where-Object { $_ -like 'FAIL*' -and $_ -notlike '*keywardend*' })
    Remove-Item Env:KEYWARDEN_LANG
    if ($fails) { $problems += 'browser'; $fails | ForEach-Object { Bad ((M 'browser link: {0}') -f ($_ -replace '^FAIL\s*', '')) } } else { Ok (M 'browser link') }
    if ($onWindows) {
      if (([Environment]::GetEnvironmentVariable('Path', 'User') -split ';') -notcontains $dir) { $problems += 'path'; Bad (M 'kw is not in PATH') }
      if (-not (Test-Path $lnk)) { $problems += 'shortcut'; Bad (M 'no shortcut in the Start menu') }
    }
    if ($talk) {
      $text = @{
        files    = (M 'put the missing programs back (downloads {0})') -f $tag
        browser  = M 'register the browser link again'
        path     = M 'add kw to PATH'
        shortcut = M 'put the shortcut back into the Start menu'
      }
      Write-Host ("`n  " + (M 'What to do?'))
      for ($i = 0; $i -lt $problems.Count; $i++) { Write-Host ("    {0}) {1}" -f ($i + 1), $text[$problems[$i]]) }
      if ($problems.Count -gt 1) { Write-Host ('    a) ' + (M 'fix all of the above')) }
      if ("v$have" -eq $tag) { Write-Host ('    r) ' + ((M 'reinstall {0}') -f $tag)) } else { Write-Host ('    u) ' + ((M 'update to {0}') -f $tag)) }
      Write-Host ('    c) ' + (M 'choose the optional parts (browser link, SSH agent)'))
      Write-Host ('    l) ' + $other)
      Write-Host ('    q) ' + (M 'nothing'))
      $a = Read-Host '  >'
      $todo = $null
      if ($a -eq 'l') { Switch-Lang; Write-Host ''; continue }
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
    $a = Read-Host ('  ' + ((M 'Enter installs everything, c lets you choose the parts, l: {0}') -f $other))
    if ($a -eq 'l') { Switch-Lang; continue }
    if ($a -eq 'c') { $parts = Choose-Parts }
  }
  break
  }
  $parts = $parts -split ' '

  $file = "keywarden-$tag-windows-x86_64.zip"
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("keywarden-" + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    Write-Host ('  ' + ((M 'downloading {0}') -f $file))
    try { Fetch "$base/$tag/$file" (Join-Path $tmp $file) } catch { throw ((M 'download failed: {0}') -f "$base/$tag/$file") }
    try { Fetch "$base/$tag/SHA256SUMS" (Join-Path $tmp 'SHA256SUMS') } catch { throw ((M 'download failed: {0}') -f 'SHA256SUMS') }
    Ok ((M 'downloaded {0:N1} MB') -f ((Get-Item (Join-Path $tmp $file)).Length / 1MB))

    $want = $null
    foreach ($line in [IO.File]::ReadAllLines((Join-Path $tmp 'SHA256SUMS'))) {
      $cols = $line -split '\s+', 2
      if ($cols.Count -eq 2 -and $cols[1].TrimStart('*') -eq $file) { $want = $cols[0] }
    }
    if (-not $want) { throw ((M '{0} is not listed in SHA256SUMS') -f $file) }
    $got = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $tmp $file)).Hash
    if ($got -ne $want) { throw ((M 'checksum mismatch for {0}, nothing installed') -f $file) }
    Ok (M 'checksum matches SHA256SUMS')

    # the checksum file sits next to the archive, so on its own it only catches a broken download;
    # the signature proves the list was made by the holder of the release key
    if ($signer -and -not $env:KEYWARDEN_UNSIGNED) {
      $keygen = Get-Command ssh-keygen -ErrorAction SilentlyContinue
      if (-not $keygen) { throw (M 'ssh-keygen is needed to check the release signature (Windows feature: OpenSSH Client)') }
      try { Fetch "$base/$tag/SHA256SUMS.sig" (Join-Path $tmp 'SHA256SUMS.sig') } catch { throw (M 'this release has no signature (SHA256SUMS.sig), nothing installed') }
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
      if ($p.ExitCode -ne 0) { throw (M 'release signature does not match, nothing installed') }
      Ok (M 'release signature is valid')
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $tmp $file), (Join-Path $tmp 'x'))
    $src = Join-Path (Join-Path $tmp 'x') "keywarden-$tag-windows-x86_64"
    foreach ($n in $names) {
      if (-not (Test-Path (Join-Path $src "$n.exe"))) { throw ((M 'the archive has no {0}, nothing installed') -f "$n.exe") }
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
    Ok ((M 'programs in {0}') -f $dir)
  }
  finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  }

  if ($onWindows) {
    if (([Environment]::GetEnvironmentVariable('Path', 'User') -split ';') -notcontains $dir) { Fix 'path' }
    Fix 'shortcut'
  }
  if ($parts -contains 'browser') { Fix 'browser' } else { Write-Host ('  . ' + ((M 'browser link skipped, later: {0}') -f 'kw browser-setup')) }
  if ($parts -contains 'ssh') { Fix 'ssh' }
  if ($onWindows -and -not $env:KEYWARDEN_NO_LAUNCH) {
    Start-Process (Join-Path $dir 'keywarden-ui.exe')
    Ok (M 'opening Keywarden')
  }

  Write-Host ("`n  " + ((M 'Keywarden {0} is installed.') -f $tag)) -ForegroundColor Green
  Write-Host ("  " + (M 'Browser extension:') + " $amo`n")
}

try { Install-Keywarden } catch { Write-Host "  x $($_.Exception.Message)" -ForegroundColor Red }
