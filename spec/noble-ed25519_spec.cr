require "./spec_helper"

require "big"

PRIVATE_KEY = hexToBytes("a665a45920422f9d417e4867ef")
MESSAGE = Bytes.new([135, 79, 153, 96, 197, 210, 183, 169, 181, 250, 211, 131, 225, 186, 68, 113, 158, 187, 116, 58])
WRONG_MESSAGE = Bytes.new([ 88, 157, 140, 127, 29, 160, 162, 75, 192, 123, 115, 129, 173, 72, 177, 207, 194, 17, 175, 28])

# Caching slows it down 2-3x
def hexToBytes(hex : String) : Bytes
  raise Error.new("hexToBytes: received invalid unpadded hex") unless hex.size % 2 == 0
  array = Bytes.new(hex.size // 2)
  i = 0
  while i < array.length   # for (i = 0 i < array.length i++)
    j = i * 2
    hexByte = hex.slice(j, j + 2)
    byte = Number.parseInt(hexByte, 16)
    array[i] = byte
    i += 1
  end
  return array
end

module Helper
  def to_bytes(hex : String) : Bytes
    hex = num.to_s(16)
    hex = hex.rjust(64, '0')
    Bytes.new(hex.size // 2) do |i|
      let j = i * 2;
      hex[j, 2].to_u8(16)
    end
  end

  def to_bytes(num : BigInt) : Bytes
    hex = num.to_s(16)
    hex = hex.rjust(64, '0')
    Bytes.new(hex.size // 2) do |i|
      j = i * 2
      hex[j, 2].to_u8(16)
    end
  end

  RAND = Random.new
  def rand_hex_string(length)
    RAND.hex(length)[0, length]
  end

  def rand_bigint(min : BigInt, max : BigInt) : BigInt
    diff = max - min
    min + RAND.rand(diff)
  end
end

include Helper

describe Noble::Ed25519 do
  before_each do
    Noble::Ed25519::Utils.precompute(8)
  end

  it "should not accept >32byte private keys" do
    invalidPriv = BigInt.new("100000000000000000000000000000000000009000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000090000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800073278156000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    expect_raises(Exception) do
      Noble::Ed25519.getPublicKey(invalidPriv)
    end
  end

  it "should verify just signed message" do
    message = rand_hex_string(32)
    privateKey = rand_bigint(Noble::Ed25519::Two, Noble::Ed25519::Curve::N)
    publicKey = Noble::Ed25519.getPublicKey(to_bytes(privateKey))
    signature = Noble::Ed25519.sign(to_bytes(message), to_bytes(privateKey))
    publicKey.size.should eq(32)
    signature.size.should eq(64)
    Noble::Ed25519.verify(signature, to_bytes(message), publicKey).should be_true
  end
end
