#$ brew tap owner/repo https://github.com/owner/repo.git
#$ brew install name-of-formula
class WagyuBin < Formula
  version '0.6.0'
  desc "<FILL IN>"
  homepage "https://github.com/ArgusHQ/wagyu"

  if OS.mac?
      url "https://github.com/ArgusHQ/wagyu/releases/download/#{version}/wagyu-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "7d11fed4c587ce7a07b330ff9c1cdc787a0532e5f6b057ce87c0da236d2f807a"
  elsif OS.linux?
      url "https://github.com/ArgusHQ/wagyu/releases/download/#{version}/wagyu-#{version}-x86_64-unknown-linux-musl.tar.gz"
      sha256 "89577c8e4188ab59e298fadfc046b5763640c111ffdd9c96527839dd50e6487b"
  end

  def install
    bin.install "wagyu"
  end
end