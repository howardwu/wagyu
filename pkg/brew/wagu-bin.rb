class WaguBin < Formula
  version '0.5.0'
  desc "Wagu allows users to generate wallets for cryptocurrencies"
  homepage "https://crates.io/crates/wagu"

  if OS.mac?
      # URL format assumes you're using https://github.com/japaric/trust to generate binaries
      url "https://github.com/ArgusHQ/wagu/releases/download/#{version}/wagu-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "UPDATE_AFTER_BUILD"
  elsif OS.linux?
      url "https://github.com/ArgusHQ/wagu/releases/download/#{version}/wagu-#{version}-x86_64-unknown-linux-musl.tar.gz"
      sha256 "UPDATE_AFTER_BUILD"
  end

  def install
    # Name of the binary
    bin.install "wagu"
  end

  test do
    assert_match "wagu v#{version}", shell_output("#{bin}/wagu --version", 2)
  end
end