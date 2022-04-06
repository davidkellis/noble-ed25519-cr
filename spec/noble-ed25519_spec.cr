require "./spec_helper"

require "big"
require "extlib"

PRIVATE_KEY = "00000000000000000000000000000000000000a665a45920422f9d417e4867ef".hex_to_bytes
MESSAGE = [135, 79, 153, 96, 197, 210, 183, 169, 181, 250, 211, 131, 225, 186, 68, 113, 158, 187, 116, 58].to_bytes
WRONG_MESSAGE = [88, 157, 140, 127, 29, 160, 162, 75, 192, 123, 115, 129, 173, 72, 177, 207, 194, 17, 175, 28].to_bytes

module Helper
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

describe "test assumptions" do
  it "private key should equal expected value" do
    PRIVATE_KEY.should eq [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 166, 101, 164, 89, 32, 66, 47, 157, 65, 126, 72, 103, 239].to_bytes
  end
end

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

  describe "verify" do
    it "should verify just signed message" do
      message = rand_hex_string(32)
      privateKey = rand_bigint(Noble::Ed25519::Two, Noble::Ed25519::Curve::N)
      publicKey = Noble::Ed25519.getPublicKey(to_bytes(privateKey))
      signature = Noble::Ed25519.sign(message.hex_to_bytes, to_bytes(privateKey))
      publicKey.size.should eq(32)
      signature.size.should eq(64)
      Noble::Ed25519.verify(signature, message.hex_to_bytes, publicKey).should be_true
    end

    it "should sign and verify" do
      publicKey = Noble::Ed25519.getPublicKey(PRIVATE_KEY)
      signature = Noble::Ed25519.sign(MESSAGE, PRIVATE_KEY)
      Noble::Ed25519.verify(signature, MESSAGE, publicKey).should be_true
    end
    
    it "should not verify signature with wrong public key" do
      publicKey = Noble::Ed25519.getPublicKey(12.to_big_i)
      signature = Noble::Ed25519.sign(MESSAGE, PRIVATE_KEY)
      Noble::Ed25519.verify(signature, MESSAGE, publicKey).should be_false
    end
    
    it "should not verify signature with wrong hash" do
      publicKey = Noble::Ed25519.getPublicKey(PRIVATE_KEY)
      signature = Noble::Ed25519.sign(MESSAGE, PRIVATE_KEY)
      Noble::Ed25519.verify(signature, WRONG_MESSAGE, publicKey).should be_false
    end
  end

  describe "BASE_POINT.multiply()" do
    # // https://xmr.llcoins.net/addresstests.html
    it "should create right publicKey without SHA-512 hashing TEST 1" do
      publicKey = Noble::Ed25519::Point::BASE.multiply("90af56259a4b6bfbc4337980d5d75fbe3c074630368ff3804d33028e5dbfa77".hex_to_bigint)
      publicKey.toHex.should eq("0f3b913371411b27e646b537e888f685bf929ea7aab93c950ed84433f064480d")
    end

    it "should create right publicKey without SHA-512 hashing TEST 2" do
      publicKey = Noble::Ed25519::Point::BASE.multiply("364e8711a60780382a5d57b061c126f039940f28a9e91fe039d4d3094d8b88".hex_to_bigint)
      publicKey.toHex.should eq("ad545340b58610f0cd62f17d55af1ab11ecde9c084d5476865ddb4dbda015349")
    end

    it "should create right publicKey without SHA-512 hashing TEST 3" do
      publicKey = Noble::Ed25519::Point::BASE.multiply("b9bf90ff3abec042752cac3a07a62f0c16cfb9d32a3fc2305d676ec2d86e941".hex_to_bigint)
      publicKey.toHex.should eq("e097c4415fe85724d522b2e449e8fd78dd40d20097bdc9ae36fe8ec6fe12cb8c")
    end

    it "should create right publicKey without SHA-512 hashing TEST 4" do
      publicKey = Noble::Ed25519::Point::BASE.multiply("69d896f02d79524c9878e080308180e2859d07f9f54454e0800e8db0847a46e".hex_to_bigint)
      publicKey.toHex.should eq("f12cb7c43b59971395926f278ce7c2eaded9444fbce62ca717564cb508a0db1d")
    end
  end

  describe "getSharedSecret" do
    it "should convert base point to montgomery using toX25519" do
      Noble::Ed25519::Point::BASE.toX25519.to_hex.should eq(Noble::Ed25519::Curve25519::BASE_POINT_U)
    end


  end
end
