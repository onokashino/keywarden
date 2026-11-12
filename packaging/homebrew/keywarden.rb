# Formula for the onokashino/homebrew-tap tap. Updated by .github/workflows/packages.yml.
class Keywarden < Formula
  desc "Keyboard-first password manager on the KeePass format (KDBX 4)"
  homepage "https://onokashino.github.io/keywarden/"
  version "0.1.0"
  url "https://github.com/onokashino/keywarden/releases/download/v#{version}/keywarden-v#{version}-macos-arm64.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "GPL-3.0-or-later"

  depends_on arch: :arm64
  depends_on :macos

  def install
    bin.install "keywardend", "kw", "keywarden-ui", "keywarden-host"
  end

  def caveats
    <<~EOS
      Connect the browser extension:  kw browser-setup
      Launcher hotkey: Shortcuts app, "Run Shell Script" #{opt_bin}/keywarden-ui --launcher
    EOS
  end

  test do
    assert_match "Usage", shell_output("#{bin}/kw --help")
  end
end
