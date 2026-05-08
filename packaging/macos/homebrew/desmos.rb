# Homebrew formula for Desmos connection bonding VPN.
#
# Install: brew install --build-from-source desmos
# Or tap:  brew tap KilimcininKorOglu/desmos && brew install desmos

class Desmos < Formula
  desc "Cross-platform connection bonding VPN"
  homepage "https://github.com/KilimcininKorOglu/desmos"
  url "https://github.com/KilimcininKorOglu/desmos/archive/v1.0.0.tar.gz"
  sha256 "a32edaa89a1f00dba32e1af98f13cc1b59a637b9fbba0babd60492eca01d7e07"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "build", "--release", "--locked"
    bin.install "target/release/desmos"

    # Install documentation.
    doc.install "README.md"
    doc.install Dir["docs/*"]
  end

  def caveats
    <<~EOS
      Desmos requires root privileges for TUN device creation.
      Run with: sudo desmos up

      Configuration: /etc/desmos/config.toml
      See: desmos config generate
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/desmos version")
  end
end
