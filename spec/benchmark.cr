require "benchmark"

require "./spec_helper"

module Helper
  def to_bytes(str : String) : Bytes
    hex = str.rjust(64, '0')
    Bytes.new(hex.size // 2) do |i|
      j = i * 2
      hex[j, 2].to_u8(16)
    end
  end

  def to_bytes(num : BigInt) : Bytes
    hex = num.to_s(16)
    to_bytes(hex)
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

def main
  private_key = to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60".hex_to_bigint)
  public_key = Noble::Ed25519.getPublicKey(private_key)
  
  # getPublicKey
  count = 1000
  private_keys = count.times.map { Noble::Ed25519::Utils.randomPrivateKey() }.to_a
  i = 0
  
  # sign
  msg = to_bytes("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
  signature = Noble::Ed25519.sign(msg, private_key)

  Benchmark.ips do |x|
    x.report("Utils.randomPrivateKey()") { Noble::Ed25519::Utils.randomPrivateKey() }
    x.report("getPublicKey()") do
      Noble::Ed25519.getPublicKey(private_keys[i % 1000])
      i += 1
    end
    x.report("sign()") { Noble::Ed25519.sign(msg, private_key) }
    x.report("verify()") { Noble::Ed25519.verify(signature, msg, public_key) }
    x.report("verify()") { Noble::Ed25519.verify(signature, msg, public_key) }
    x.report("Point.fromHex") { Noble::Ed25519::Point.fromHex(public_key) }
  end
end

main