require "./spec_helper"

require "big"
require "extlib"

PRIVATE_KEY = to_bytes("a665a45920422f9d417e4867ef")
MESSAGE = [135, 79, 153, 96, 197, 210, 183, 169, 181, 250, 211, 131, 225, 186, 68, 113, 158, 187, 116, 58].to_bytes
WRONG_MESSAGE = [88, 157, 140, 127, 29, 160, 162, 75, 192, 123, 115, 129, 173, 72, 177, 207, 194, 17, 175, 28].to_bytes

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

  context "conversion functions" do
    it "converts bytes to hex" do
      Noble::Ed25519.bytesToHex(MESSAGE).should eq MESSAGE.to_hex
    end

    it "converts hex string to bytes" do
      Noble::Ed25519.hexToBytes("a665a45920422f9d417e4867ef").should eq [166, 101, 164, 89, 32, 66, 47, 157, 65, 126, 72, 103, 239].to_bytes
    end

    it "converts BigInt to 32 byte big endian byte sequence" do
      Noble::Ed25519.numberTo32BytesBE("27742317777372353535851937790883648493".to_big_i).should eq [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 222, 249, 222, 162, 247, 156, 214, 88, 18, 99, 26, 92, 245, 211, 237].to_bytes
    end

    it "converts BigInt to 32 byte little endian byte sequence" do
      Noble::Ed25519.numberTo32BytesLE("27742317777372353535851937790883648493".to_big_i).should eq [237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_bytes
    end

    it "should compute mod CURVE::P" do
      (Noble::Ed25519.mod("27742317777372353535851937790883648493".to_big_i) ** 2).should eq "769636195660710121963126688387520540573743352701667656699307335599181171049".to_big_i
    end

    it "inverts number" do
      num = "769636195660710121963126688387520540573743352701667656699307335599181171049".to_big_i
      Noble::Ed25519.invert(num).should eq "18727814700475809736293234788260555231456469736277112044268635736416120439616".to_big_i
    end

    it "inverts batch of numbers" do
      Noble::Ed25519.invertBatch([1.to_big_i, 2.to_big_i, 4.to_big_i], 21.to_big_i).should eq [1, 11, 16]
    end

    it "computes pow2" do
      Noble::Ed25519.pow2(30.to_big_i, 4.to_big_i).should eq (30.to_big_i ** (2 ** 4))
    end

    it "computes pow_2_252_3" do
      num = "769636195660710121963126688387520540573743352701667656699307335599181171049".to_big_i
      Noble::Ed25519.pow_2_252_3(num).should eq({"2007243726052975970339153529261035180203912631570139636502564328030873469281".to_big_i, "52864636761835200299101173910121901953771021227763758333640898492888052065337".to_big_i})
    end

    it "computes uvRatio" do
      Noble::Ed25519.uvRatio("27742317777372353535851937790883648493".to_big_i, "198769872436918376213501958703920938752386".to_big_i).should eq({isValid: false, value: "33163897333317007419663107070771352354920589001556313524914073390963493288394".to_big_i})
    end

    it "computes sha512ModqLE" do
      Noble::Ed25519.sha512ModqLE([12, 45].to_bytes).should eq "1496564937568173540830439562996302377934504166425150197954509365085523985106".to_big_i
    end

    it "computes adjustBytes25519" do
      Noble::Ed25519.adjustBytes25519([12, 45, 29, 27, 245, 25, 1, 0, 64, 187, 12, 45, 29, 27, 245, 25, 12, 45, 29, 27, 245, 25, 1, 0, 64, 187, 12, 45, 29, 27, 245, 25].to_bytes).should eq [8, 45, 29, 27, 245, 25, 1, 0, 64, 187, 12, 45, 29, 27, 245, 25, 12, 45, 29, 27, 245, 25, 1, 0, 64, 187, 12, 45, 29, 27, 245, 89].to_bytes
    end

    it "computes decodeScalar25519" do
      Noble::Ed25519.decodeScalar25519("a665a45920422f9d417e4867ef920422a665a45920422f9d417e4867ef920422").should eq "44334740658690092479172493905085013329736094120839359355401836069192844207520".to_big_i
    end
  end

  it "should not accept >32byte private keys" do
    invalidPriv = BigInt.new("100000000000000000000000000000000000009000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000090000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800073278156000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    expect_raises(Exception) do
      Noble::Ed25519.getPublicKey(invalidPriv)
    end
  end

  describe "key primitives" do
    it "getExtendedPublicKey" do
      head, prefix, scalar, point, pointBytes = Noble::Ed25519.getExtendedPublicKey(PRIVATE_KEY)
      head.should eq [128, 22, 244, 174, 242, 184, 243, 242, 167, 158, 97, 38, 31, 78, 189, 6, 100, 112, 241, 78, 51, 33, 205, 89, 118, 48, 7, 182, 0, 98, 236, 109].to_bytes
      prefix.should eq [79, 166, 233, 152, 248, 238, 22, 118, 193, 139, 243, 78, 115, 113, 204, 49, 15, 197, 185, 93, 246, 58, 130, 240, 67, 120, 235, 20, 105, 5, 86, 216 ].to_bytes
      scalar.should eq "6297719329181941818464811366542144281012346280162365974104312725502870757106".to_big_i
      point.x.should eq "13663649446542597719550959276437970190593665354523449128466207698868480675936".to_big_i
      point.y.should eq "52410848636940328811284449235140577725393652610851387856422556910462868432345".to_big_i
      pointBytes.should eq [217, 165, 208, 247, 73, 44, 4, 181, 237, 154, 236, 245, 8, 2, 146, 13, 63, 34, 199, 5, 70, 70, 14, 49, 10, 90, 212, 68, 53, 125, 223, 115 ].to_bytes
    end

    it "getPublicKey" do
      pointBytes = Noble::Ed25519.getPublicKey(PRIVATE_KEY)
      pointBytes.should eq [217, 165, 208, 247, 73, 44, 4, 181, 237, 154, 236, 245, 8, 2, 146, 13, 63, 34, 199, 5, 70, 70, 14, 49, 10, 90, 212, 68, 53, 125, 223, 115 ].to_bytes
    end
  end

  describe "Point" do
    it "serializes" do
      x = "13663649446542597719550959276437970190593665354523449128466207698868480675936".to_big_i
      y = "52410848636940328811284449235140577725393652610851387856422556910462868432345".to_big_i
      p = Noble::Ed25519::Point.new(x, y)
      p.toRawBytes.should eq [217, 165, 208, 247, 73, 44, 4, 181, 237, 154, 236, 245, 8, 2, 146, 13, 63, 34, 199, 5, 70, 70, 14, 49, 10, 90, 212, 68, 53, 125, 223, 115].to_bytes
      p.toHex.should eq "d9a5d0f7492c04b5ed9aecf50802920d3f22c70546460e310a5ad444357ddf73"
      p.toX25519.should eq [226, 167, 236, 215, 164, 98, 114, 37, 42, 31, 98, 136, 35, 58, 104, 117, 13, 130, 161, 52, 114, 220, 82, 42, 93, 132, 35, 128, 147, 50, 47, 79].to_bytes
    end

    it "builds from a hex string" do
      x = "13663649446542597719550959276437970190593665354523449128466207698868480675936".to_big_i
      y = "52410848636940328811284449235140577725393652610851387856422556910462868432345".to_big_i
      p = Noble::Ed25519::Point.new(x, y)
      hex = p.toHex

      p2 = Noble::Ed25519::Point.fromHex(hex)

      p2.should eq p
    end
  end

  describe "ExtendedPoint" do
    it "serializes" do
      x = "13663649446542597719550959276437970190593665354523449128466207698868480675936".to_big_i
      y = "52410848636940328811284449235140577725393652610851387856422556910462868432345".to_big_i
      p = Noble::Ed25519::Point.new(x, y)
      ep = Noble::Ed25519::ExtendedPoint.fromAffine(p)
      ep.x.should eq x
      ep.y.should eq y
      ep.z.should eq 1.to_big_i
      ep.t.should eq "3333821308574899331449657780017777373778814702650532606330657819633145467729".to_big_i
    end

    it "builds from affine" do
      x = "13663649446542597719550959276437970190593665354523449128466207698868480675936".to_big_i
      y = "52410848636940328811284449235140577725393652610851387856422556910462868432345".to_big_i
      p = Noble::Ed25519::Point.new(x, y)
      ep = Noble::Ed25519::ExtendedPoint.fromAffine(p)
      ep.x.should eq x
      ep.y.should eq y
      ep.z.should eq 1.to_big_i
      ep.t.should eq "3333821308574899331449657780017777373778814702650532606330657819633145467729".to_big_i
    end

    it "negates" do
      x = "13663649446542597719550959276437970190593665354523449128466207698868480675936".to_big_i
      y = "52410848636940328811284449235140577725393652610851387856422556910462868432345".to_big_i
      p = Noble::Ed25519::Point.new(x, y)
      ep = Noble::Ed25519::ExtendedPoint.fromAffine(p).negate
      ep.x.should eq "44232395172115499992234533227905983736041326978296832891262584305088084144013".to_big_i
      ep.y.should eq "52410848636940328811284449235140577725393652610851387856422556910462868432345".to_big_i
      ep.z.should eq 1.to_big_i
      ep.t.should eq "54562223310083198380335834724326176552856177630169749413398134184323419352220".to_big_i
    end

    it "multiplies" do
      x = "13663649446542597719550959276437970190593665354523449128466207698868480675936".to_big_i
      y = "52410848636940328811284449235140577725393652610851387856422556910462868432345".to_big_i
      p = Noble::Ed25519::Point.new(x, y)
      ep = Noble::Ed25519::ExtendedPoint.fromAffine(p)
      f = "276437970844492190593665354523449128878564225569104628".to_big_i
      ep2 = ep.multiply(f, p);
      ep2.x.should eq "22321684185565943538558315764286033780372969712381639797051747678870352647731".to_big_i
      ep2.y.should eq "38655008969693726098878720355832570031914924052594147795829808220614943511493".to_big_i
      ep2.z.should eq 1.to_big_i
      ep2.t.should eq "31822727824655136889098960564923067063356144817389259181769889501732264576329".to_big_i
    end

    it "converts toAffine" do
      x = "13663649446542597719550959276437970190593665354523449128466207698868480675936".to_big_i
      y = "52410848636940328811284449235140577725393652610851387856422556910462868432345".to_big_i
      p = Noble::Ed25519::Point.new(x, y)
      ep = Noble::Ed25519::ExtendedPoint.fromAffine(p)
      f = "276437970844492190593665354523449128878564225569104628".to_big_i
      ep2 = ep.multiply(f, p);
      p2 = ep2.toAffine
      p2.x.should eq "22321684185565943538558315764286033780372969712381639797051747678870352647731".to_big_i
      p2.y.should eq "38655008969693726098878720355832570031914924052594147795829808220614943511493".to_big_i
    end

  end

  describe "sign" do
    it "signs message with private key" do
      Noble::Ed25519.sign(MESSAGE, PRIVATE_KEY).should eq [126, 53, 132, 137, 134, 7, 9, 5, 101, 248, 41, 96, 94, 100, 244, 241, 68, 100, 234, 120, 1, 194, 16, 148, 150, 227, 147, 254, 0, 189, 23, 213, 53, 173, 180, 16, 169, 128, 123, 5, 204, 49, 120, 123, 36, 100, 113, 149, 235, 244, 141, 54, 57, 40, 114, 49, 38, 182, 224, 59, 28, 24, 71, 2].to_bytes
      Noble::Ed25519.sign(WRONG_MESSAGE, PRIVATE_KEY).should eq [250, 158, 167, 238, 93, 87, 42, 237, 2, 56, 163, 144, 32, 181, 69, 154, 87, 213, 23, 99, 5, 9, 124, 103, 75, 16, 35, 63, 240, 33, 130, 50, 112, 136, 1, 193, 246, 42, 125, 77, 167, 54, 56, 246, 196, 17, 205, 114, 115, 166, 175, 201, 244, 126, 241, 30, 0, 37, 128, 56, 92, 64, 1, 3].to_bytes
    end
  end

  describe "verify" do
    it "should verify just signed message" do
      message = rand_hex_string(32)
      privateKey = rand_bigint(Noble::Ed25519::Two, Noble::Ed25519::Curve::N)
      publicKey = Noble::Ed25519.getPublicKey(to_bytes(privateKey))
      signature = Noble::Ed25519.sign(to_bytes(message), to_bytes(privateKey))
      publicKey.size.should eq(32)
      signature.size.should eq(64)
      Noble::Ed25519.verify(signature, to_bytes(message), publicKey).should be_true
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
