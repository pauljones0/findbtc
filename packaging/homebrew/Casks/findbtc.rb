# Bootstrapped by hand against the immutable v0.2.0 release assets
# (URLs + SHA-256 verified against checksums.txt); GoReleaser
# rewrites this file on future tags once the tap token exists
# (see findbtc .goreleaser.yaml homebrew_casks.skip_upload).
# Install with:
#   brew tap pauljones0/findbtc
#   brew install pauljones0/findbtc/findbtc
cask "findbtc" do
  version "0.2.0"

  on_macos do
    on_arm do
      sha256 "e49b759879c7d8be697d5c1bb2e9694f46f64567833036363ccd926c1c13d0d6"
      url "https://github.com/pauljones0/findbtc/releases/download/v0.2.0/findbtc_0.2.0_darwin_arm64.tar.gz"
    end
    on_intel do
      sha256 "2941a78fb5c0d3e9a59984b25b8ff73b641734687c49259df0fb1e6c4d6f9223"
      url "https://github.com/pauljones0/findbtc/releases/download/v0.2.0/findbtc_0.2.0_darwin_amd64.tar.gz"
    end
  end
  on_linux do
    on_arm do
      sha256 "dd74bb4e528b044f1955137ec0101cd256d6eefbdcad5430a805f7dfa2c74a75"
      url "https://github.com/pauljones0/findbtc/releases/download/v0.2.0/findbtc_0.2.0_linux_arm64.tar.gz"
    end
    on_intel do
      sha256 "ce50b5717138a2dd45f409b82a95826a7605dad8fbff9cb537b9cdb1bc8406d6"
      url "https://github.com/pauljones0/findbtc/releases/download/v0.2.0/findbtc_0.2.0_linux_amd64.tar.gz"
    end
  end

  name "findbtc"
  desc "Find BTC wallets by scanning raw block devices"
  homepage "https://github.com/pauljones0/findbtc"

  livecheck do
    skip "Auto-generated on release."
  end

  binary "findbtc"

  # No zap stanza required
end
