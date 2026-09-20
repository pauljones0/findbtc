# Bootstrapped by hand against the immutable v9.9.9 release assets
# (URLs + SHA-256 verified against checksums.txt); GoReleaser
# rewrites this file on future tags once the tap token exists
# (see findbtc .goreleaser.yaml homebrew_casks.skip_upload).
# Install with:
#   brew tap pauljones0/findbtc
#   brew install pauljones0/findbtc/findbtc
cask "findbtc" do
  version "9.9.9"

  on_macos do
    on_arm do
      sha256 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      url "https://github.com/pauljones0/findbtc/releases/download/v9.9.9/findbtc_9.9.9_darwin_arm64.tar.gz"
    end
    on_intel do
      sha256 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      url "https://github.com/pauljones0/findbtc/releases/download/v9.9.9/findbtc_9.9.9_darwin_amd64.tar.gz"
    end
  end
  on_linux do
    on_intel do
      sha256 "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      url "https://github.com/pauljones0/findbtc/releases/download/v9.9.9/findbtc_9.9.9_linux_amd64.tar.gz"
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
