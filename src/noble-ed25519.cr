# this is a crystal port of https://github.com/paulmillr/noble-ed25519/blob/main/index.ts

require "big"
require "digest"
require "extlib"
require "weak_ref"

module Noble::Ed25519
  extend self

  alias Hex = Bytes | String
  alias PrivKey = Hex | BigInt
  alias PubKey = Hex | Point
  alias SigType = Hex | Signature

  Zero = BigInt.new(0)
  One = BigInt.new(1)
  Two = BigInt.new(2)
  BigInt256 = BigInt.new(255)
  CURVE_ORDER = Two ** BigInt.new(252) + BigInt.new("27742317777372353535851937790883648493")

  # ed25519 is Twisted Edwards curve with equation of
  # ```
  # −x² + y² = 1 − (121665/121666) * x² * y²
  # ```
  module Curve
    # Param: a
    A = BigInt.new(-1)
    # Equal to -121665/121666 over finite field.
    # Negative number is P - number, and division is invert(number, P)
    D = BigInt.new("37095705934669439343138083508754565189542113879843219016388785533085940283555")
    # Finite field 𝔽p over which we'll do calculations
    P = Noble::Ed25519::Two ** BigInt256 - BigInt.new(19)
    # Subgroup order: how many points ed25519 has
    L = CURVE_ORDER # in rfc8032 it's called l
    N =  CURVE_ORDER # backwards compatibility
    # Cofactor
    H = BigInt.new(8)
    # Base point (x, y) aka generator point
    Gx = BigInt.new("15112221349535400772501151409588531511454012693041857206046113283949847762202")
    Gy = BigInt.new("46316835694926478169428394003475163141307993866256225615783033603165251855960")
  end

  MAX_256B = Noble::Ed25519::Two ** BigInt.new(256)

  # √(-1) aka √(a) aka 2^((p-1)/4)
  SQRT_M1 = BigInt.new("19681161376707505956807079304988542015446066515923890162744021073123829784752")
  # √d aka sqrt(-486664)
  SQRT_D = BigInt.new( "6853475219497561581579357271197624642482790079785650197046958215289687604742" )
  # √(ad - 1)
  SQRT_AD_MINUS_ONE = BigInt.new( "25063068953384623474111414158702152701244531502492656460079210482610430750235" )
  # 1 / √(a-d)
  INVSQRT_A_MINUS_D = BigInt.new( "54469307008909316920995813868745141605393597292927456921205312896311721017578" )
  # 1-d²
  ONE_MINUS_D_SQ = BigInt.new( "1159843021668779879193775521855586647937357759715417654439879720876111806838" )
  # (d-1)²
  D_MINUS_ONE_SQ = BigInt.new( "40440834346308536858101042469323190826248399146238708352240133220865137265952" )

  # Extended Point works in extended coordinates: (x, y, z, t) ∋ (x=x/z, y=y/z, t=xy).
  # Default Point works in affine coordinates: (x, y)
  # https://en.wikipedia.org/wiki/Twisted_Edwards_curve#Extended_coordinates
  class ExtendedPoint
    BASE = ExtendedPoint.new(Curve::Gx, Curve::Gy, One, Noble::Ed25519.mod(Curve::Gx * Curve::Gy))
    ZERO = ExtendedPoint.new(Zero, One, One, Zero)

    def self.fromAffine(p : Point) : ExtendedPoint
      if p == Point::ZERO
        ExtendedPoint::ZERO
      else
        ExtendedPoint.new(p.x, p.y, One, Noble::Ed25519.mod(p.x * p.y))
      end
    end
    
    # Takes a bunch of Jacobian Points but executes only one
    # invert on all of them. invert is very slow operation,
    # so this improves performance massively.
    def self.toAffineBatch(points : Array(ExtendedPoint)) : Array(Point)
      toInv = Noble::Ed25519.invertBatch(points.map(&.z))
      points.map_with_index {|p, i| p.toAffine(toInv[i]) }
    end

    def self.normalizeZ(points : Array(ExtendedPoint)) : Array(ExtendedPoint)
      self.toAffineBatch(points).map {|p| fromAffine(p) }
    end


    property x : BigInt
    property y : BigInt
    property z : BigInt
    property t : BigInt

    def initialize(@x : BigInt, @y : BigInt, @z : BigInt, @t : BigInt)
    end

    # Compare one point to another.
    def equals(other : ExtendedPoint) : Bool
      x1, y1, z1 = @x, @y, @z
      x2, y2, z2 = other.x, other.y, other.z
      x1z2 = Noble::Ed25519.mod(x1 * z2)
      x2z1 = Noble::Ed25519.mod(x2 * z1)
      y1z2 = Noble::Ed25519.mod(y1 * z2)
      y2z1 = Noble::Ed25519.mod(y2 * z1)
      return x1z2 === x2z1 && y1z2 === y2z1
    end

    def ==(other : ExtendedPoint) : Bool
      equals(other)
    end

    # Inverses point to one corresponding to (x, -y) in Affine coordinates.
    def negate() : ExtendedPoint
      return ExtendedPoint.new(Noble::Ed25519.mod(-@x), @y, @z, Noble::Ed25519.mod(-@t))
    end

    # Fast algo for doubling Extended Point when curve's a=-1.
    # http://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#doubling-dbl-2008-hwcd
    # Cost: 3M + 4S + 1*a + 7add + 1*2.
    def double() : ExtendedPoint
      x1, y1, z1 = @x, @y, @z
      a = Noble::Ed25519.mod(x1 ** Noble::Ed25519::Two)
      b = Noble::Ed25519.mod(y1 ** Noble::Ed25519::Two)
      c = Noble::Ed25519.mod(Noble::Ed25519::Two * Noble::Ed25519.mod(z1 ** Noble::Ed25519::Two))
      d = Noble::Ed25519.mod(Curve::A * a)
      e = Noble::Ed25519.mod(Noble::Ed25519.mod((x1 + y1) ** Noble::Ed25519::Two) - a - b)
      g = d + b
      f = g - c
      h = d - b
      x3 = Noble::Ed25519.mod(e * f)
      y3 = Noble::Ed25519.mod(g * h)
      t3 = Noble::Ed25519.mod(e * h)
      z3 = Noble::Ed25519.mod(f * g)
      return ExtendedPoint.new(x3, y3, z3, t3)
    end

    # Fast algo for adding 2 Extended Points when curve's a=-1.
    # http://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-4
    # Cost: 8M + 8add + 2*2.
    # Note: It does not check whether the `other` point is valid.
    def add(other : ExtendedPoint)
      # assertExtPoint(other)
      x1, y1, z1, t1 = @x, @y, @z, @t
      x2, y2, z2, t2 = other.x, other.y, other.z, other.t
      a = Noble::Ed25519.mod((y1 - x1) * (y2 + x2))
      b = Noble::Ed25519.mod((y1 + x1) * (y2 - x2))
      f = Noble::Ed25519.mod(b - a)
      if f === Zero
        self.double()  # Same point.
      else
        c = Noble::Ed25519.mod(z1 * Noble::Ed25519::Two * t2)
        d = Noble::Ed25519.mod(t1 * Noble::Ed25519::Two * z2)
        e = d + c
        g = b + a
        h = d - c
        x3 = Noble::Ed25519.mod(e * f)
        y3 = Noble::Ed25519.mod(g * h)
        t3 = Noble::Ed25519.mod(e * h)
        z3 = Noble::Ed25519.mod(f * g)
        ExtendedPoint.new(x3, y3, z3, t3)
      end
    end

    def subtract(other : ExtendedPoint) : ExtendedPoint
      return self.add(other.negate())
    end

    private def precomputeWindow(w : Int) : Array(ExtendedPoint)
      windows = 1 + 256 / w
      points : Array(ExtendedPoint) = [] of ExtendedPoint
      p : ExtendedPoint = self
      base = p
      window = 0
      while window < windows  # for (window = 0 window < windows window++)
        base = p
        points.push(base)
        i = 1
        while i < 2 ** (w - 1)   # for (i = 1 i < 2 ** (W - 1) i++)
          base = base.add(p)
          points.push(base)
          i += 1
        end
        p = base.double()
        window += 1
      end
      return points
    end

    private def wNAF(n : BigInt, affinePoint : Point? = nil) : ExtendedPoint
      if affinePoint.nil? && self == ExtendedPoint::BASE
        affinePoint = Point::BASE
      end
      w = affinePoint.try(&._WINDOW_SIZE) || 1
      raise ArgumentError.new("Point#wNAF: Invalid precomputation window, must be power of 2") if 256 % w != 0

      precomputes : Array(ExtendedPoint) = 
        if affinePoint && (points = Noble::Ed25519::PointPrecomputes[WeakRef.new(affinePoint)]?)
          points
        else
          points = precomputeWindow(w)
          if affinePoint && w != 1
            points = ExtendedPoint.normalizeZ(points)
            Noble::Ed25519::PointPrecomputes[WeakRef.new(affinePoint)] = points
          end
          points
        end
      

      p = ExtendedPoint::ZERO
      f = ExtendedPoint::ZERO

      windows = 1 + 256 / w
      windowSize = 2 ** (w - 1)
      mask = BigInt.new(2 ** w - 1) # Create mask with W ones: 0b1111 for W=4 etc.
      maxNumber = 2 ** w
      shiftBy = BigInt.new(w)

      window = 0
      while window < windows  # for (window = 0 window < windows window++)
        offset = window * windowSize
        # Extract W bits.
        wbits = n & mask

        # Shift number by W bits.
        n >>= shiftBy

        # If the bits are bigger than max size, we'll split those.
        # +224 => 256 - 32
        if wbits > windowSize
          wbits -= maxNumber
          n += One
        end

        # Check if we're onto Zero point.
        # Add random point inside current window to f.
        if wbits == 0
          pr = precomputes[offset]
          if window % 2 != 0
            pr = pr.negate()
          end
          f = f.add(pr)
        else
          cached = precomputes[offset + wbits.abs - 1]
          if wbits < 0
            cached = cached.negate()
          end
          p = p.add(cached)
        end
        window += 1
      end
      ExtendedPoint.normalizeZ([p, f])[0]
    end

    # Constant time multiplication.
    # Uses wNAF method. Windowed method may be 10% faster,
    # but takes 2x longer to generate and consumes 2x memory.
    def multiply(scalar : Int, affinePoint : Point?) : ExtendedPoint
      wNAF(Noble::Ed25519.normalizeScalar(scalar, Curve::L), affinePoint)
    end

    # Non-constant-time multiplication. Uses double-and-add algorithm.
    # It's faster, but should only be used when you don't care about
    # an exposed private key e.g. sig verification.
    # Allows scalar bigger than curve order, but less than 2^256
    def multiplyUnsafe(scalar : Int) : ExtendedPoint
      n = Noble::Ed25519.normalizeScalar(scalar, Curve::L, false)
      g = ExtendedPoint::BASE
      p0 = ExtendedPoint::ZERO
      if n == Zero
        p0
      elsif self.equals(p0) || n === One
        self
      elsif self.equals(g)
        wNAF(n)
      else
        p = p0
        d : ExtendedPoint = self
        while n > Zero
          if n & One != 0
            p = p.add(d)
          end
          d = d.double()
          n >>= One
        end
        p
      end
    end

    def isSmallOrder() : Bool
      self.multiplyUnsafe(Curve::H).equals(ExtendedPoint::ZERO)
    end

    def isTorsionFree() : Bool
      self.multiplyUnsafe(Curve::L).equals(ExtendedPoint::ZERO)
    end

    # Converts Extended point to default (x, y) coordinates.
    # Can accept precomputed Z^-1 - for example, from invertBatch.
    def toAffine(invZ : BigInt = Noble::Ed25519.invert(@z)) : Point
      x, y, z = @x, @y, @z
      ax = Noble::Ed25519.mod(x * invZ)
      ay = Noble::Ed25519.mod(y * invZ)
      zz = Noble::Ed25519.mod(z * invZ)
      raise Exception.new("invZ was invalid") if zz != One
      Point.new(ax, ay)
    end
  end

  #**
  # Each ed25519/ExtendedPoint has 8 different equivalent points. This can be
  # a source of bugs for protocols like ring signatures. Ristretto was created to solve this.
  # Ristretto point operates in X:Y:Z:T extended coordinates like ExtendedPoint,
  # but it should work in its own namespace: do not combine those two.
  # https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ristretto255-decaf448
  #/
  class RistrettoPoint
    BASE = RistrettoPoint.new(ExtendedPoint::BASE)
    ZERO = RistrettoPoint.new(ExtendedPoint::ZERO)

    property ep : ExtendedPoint

    # Private property to discourage combining ExtendedPoint + RistrettoPoint
    # Always use Ristretto encoding/decoding instead.
    def initialize(@ep : ExtendedPoint)
    end

    # Computes Elligator map for Ristretto
    # https://ristretto.group/formulas/elligator.html
    private def self.calcElligatorRistrettoMap(r0 : BigInt) : ExtendedPoint
      r = Noble::Ed25519.mod(SQRT_M1 * r0 * r0) # 1
      ns = Noble::Ed25519.mod((r + One) * ONE_MINUS_D_SQ) # 2
      c = BigInt.new(-1) # 3
      d = Noble::Ed25519.mod((c - Curve::D * r) * Noble::Ed25519.mod(r + Curve::D)) # 4
      pair = uvRatio(ns, d) # 5
      ns_d_is_sq = pair[:isValid]
      s = pair.value
      s_ = Noble::Ed25519.mod(s * r0) # 6
      s_ = Noble::Ed25519.mod(-s_) unless edIsNegative(s_)
      s = s_ unless ns_d_is_sq # 7
      c = r unless ns_d_is_sq # 8
      nt = Noble::Ed25519.mod(c * (r - One) * D_MINUS_ONE_SQ - d) # 9
      s2 = s * s
      w0 = Noble::Ed25519.mod((s + s) * d) # 10
      w1 = Noble::Ed25519.mod(nt * SQRT_AD_MINUS_ONE) # 11
      w2 = Noble::Ed25519.mod(One - s2) # 12
      w3 = Noble::Ed25519.mod(One + s2) # 13
      ExtendedPoint.new(Noble::Ed25519.mod(w0 * w3), Noble::Ed25519.mod(w2 * w1), Noble::Ed25519.mod(w1 * w3), Noble::Ed25519.mod(w0 * w2))
    end

    #**
    # Takes uniform output of 64-bit hash function like sha512 and converts it to `RistrettoPoint`.
    # The hash-to-group operation applies Elligator twice and adds the results.
    # **Note:** this is one-way map, there is no conversion from point to hash.
    # https://ristretto.group/formulas/elligator.html
    # @param hex 64-bit output of a hash function
    #/
    def self.hashToCurve(hex : Hex) : RistrettoPoint
      hex = ensureBytes(hex, 64)
      r1 = bytes255ToNumberLE(hex.slice(0, 32))
      r1_ = self.calcElligatorRistrettoMap(r1)
      r2 = bytes255ToNumberLE(hex.slice(32, 64))
      r2_ = self.calcElligatorRistrettoMap(r2)
      RistrettoPoint.new(r1_.add(r2_))
    end

    #**
    # Converts ristretto-encoded string to ristretto point.
    # https://ristretto.group/formulas/decoding.html
    # @param hex Ristretto-encoded 32 bytes. Not every 32-byte string is valid ristretto encoding
    #/
    def self.fromHex(hex : Hex) : RistrettoPoint
      hex = ensureBytes(hex, 32)
      emsg = "RistrettoPoint.fromHex: the hex is not valid encoding of RistrettoPoint"
      s = bytes255ToNumberLE(hex)
      # 1. Check that s_bytes is the canonical encoding of a field element, or else abort.
      # 3. Check that s is non-negative, or else abort
      raise Exception.new(emsg) if !equalBytes(numberTo32BytesLE(s), hex) || edIsNegative(s)
      s2 = Noble::Ed25519.mod(s * s)
      u1 = Noble::Ed25519.mod(One + Curve::A * s2) # 4 (a is -1)
      u2 = Noble::Ed25519.mod(One - Curve::A * s2) # 5
      u1_2 = Noble::Ed25519.mod(u1 * u1)
      u2_2 = Noble::Ed25519.mod(u2 * u2)
      v = Noble::Ed25519.mod(Curve::A * Curve::D * u1_2 - u2_2) # 6
      pair = invertSqrt(Noble::Ed25519.mod(v * u2_2)) # 7
      i = pair.value
      dx = Noble::Ed25519.mod(i * u2) # 8
      dy = Noble::Ed25519.mod(i * dx * v) # 9
      x = Noble::Ed25519.mod((s + s) * dx) # 10
      x = Noble::Ed25519.mod(-x) if edIsNegative(x)  # 10
      y = Noble::Ed25519.mod(u1 * dy) # 11
      t = Noble::Ed25519.mod(x * y) # 12
      raise Exception.new(emsg) if !pair.isValid || edIsNegative(t) || y == Zero
      RistrettoPoint.new(ExtendedPoint.new(x, y, One, t))
    end

    #**
    # Encodes ristretto point to Bytes.
    # https ://ristretto.group/formulas/encoding.html
    #/
    def toRawBytes() : Bytes
      x, y, z, t = @ep.x, @ep.y, @ep.z, @ep.t
      u1 = Noble::Ed25519.mod(Noble::Ed25519.mod(z + y) * Noble::Ed25519.mod(z - y)) # 1
      u2 = Noble::Ed25519.mod(x * y) # 2
      # Square root always exists
      pair = invertSqrt(Noble::Ed25519.mod(u1 * u2 ** Noble::Ed25519::Two)) # 3
      invsqrt = pair.value
      d1 = Noble::Ed25519.mod(invsqrt * u1) # 4
      d2 = Noble::Ed25519.mod(invsqrt * u2) # 5
      zInv = Noble::Ed25519.mod(d1 * d2 * t) # 6
      d : BigInt = BigInt.new(0) # 7
      if (edIsNegative(t * zInv))
        _x = Noble::Ed25519.mod(y * SQRT_M1)
        _y = Noble::Ed25519.mod(x * SQRT_M1)
        x = _x
        y = _y
        d = Noble::Ed25519.mod(d1 * INVSQRT_A_MINUS_D)
      else
        d = d2 # 8
      end
      y = Noble::Ed25519.mod(-y) if edIsNegative(x * zInv) # 9
      s = Noble::Ed25519.mod((z - y) * d) # 10 (check footer's note, no sqrt(-a))
      s = Noble::Ed25519.mod(-s) if edIsNegative(s)
      numberTo32BytesLE(s) # 11
    end

    def toHex() : String
      return bytesToHex(self.toRawBytes())
    end

    def toString() : String
      return self.toHex()
    end

    # Compare one point to another.
    def equals(other : RistrettoPoint) : Bool
      assertRstPoint(other)
      a = self.ep
      b = other.ep
      # (x1 * y2 == y1 * x2) | (y1 * y2 == x1 * x2)
      one = Noble::Ed25519.mod(a.x * b.y) == Noble::Ed25519.mod(a.y * b.x)
      two = Noble::Ed25519.mod(a.y * b.y) == Noble::Ed25519.mod(a.x * b.x)
      return one || two
    end

    def ==(other : RistrettoPoint) : Bool
      equals(other)
    end

    def add(other : RistrettoPoint) : RistrettoPoint
      assertRstPoint(other)
      return RistrettoPoint.new(self.ep.add(other.ep))
    end

    def subtract(other : RistrettoPoint) : RistrettoPoint
      assertRstPoint(other)
      return RistrettoPoint.new(self.ep.subtract(other.ep))
    end

    def multiply(scalar : Int) : RistrettoPoint
      return RistrettoPoint.new(self.ep.multiply(scalar))
    end

    def multiplyUnsafe(scalar : Int) : RistrettoPoint
      return RistrettoPoint.new(self.ep.multiplyUnsafe(scalar))
    end
  end

  # Stores precomputed values for points.
  PointPrecomputes = Hash(WeakRef(Point), Array(ExtendedPoint)).new()    # Todo: This should be a WeakMap, to retain the same semantics as the original implementation in typescript

  #**
  # Default Point works in affine coordinates: (x, y)
  #/
  class Point
    # Base point aka generator
    # public_key = Point::BASE * private_key
    BASE = Point.new(Noble::Ed25519::Curve::Gx, Noble::Ed25519::Curve::Gy)
    # Identity point aka point at infinity
    # point = point + zero_point
    ZERO = Point.new(Zero, One)
    
    # We calculate precomputes for elliptic curve point multiplication
    # using windowed method. This specifies window size and
    # stores precomputed values. Usually only base point would be precomputed.
    property _WINDOW_SIZE : Int32
    property x : BigInt
    property y : BigInt

    def initialize(@x : BigInt, @y : BigInt)
      @_WINDOW_SIZE = 8
    end

    # Note: This method is not in the original typescript implementation.
    # This method only exists to retain the WeakMap semantics that were encoded in the original implementation
    # through the use of WeakMap(Point, Array(ExtendedPoint)) in typescript.
    def finialize
      Noble::Ed25519::PointPrecomputes.delete(WeakRef.new(self))
    end

    # "Private method", don't use it directly.
    def _setWindowSize(windowSize : Int32)
      @_WINDOW_SIZE = windowSize
      Noble::Ed25519::PointPrecomputes.delete(WeakRef.new(self))
    end

    # Converts hash string or Bytes to Point.
    # Uses algo from RFC8032 5.1.3.
    def self.fromHex(hex : Hex, strict = true)
      hex_bytes = Noble::Ed25519.ensureBytes(hex, 32)
      
      # 1.  First, interpret the string as an integer in little-endian
      # representation. Bit 255 of this number is the least significant
      # bit of the x-coordinate and denote this value x_0.  The
      # y-coordinate is recovered simply by clearing this bit.  If the
      # resulting value is >= p, decoding fails.
      normed = hex_bytes.clone
      normed[31] = hex_bytes[31] & ~0x80
      y = Noble::Ed25519.bytesToNumberLE(normed)

      raise Exception.new("Expected 0 < hex < P") if strict && y >= Curve::P
      raise Exception.new("Expected 0 < hex < 2**256") if !strict && y >= MAX_256B

      # 2.  To recover the x-coordinate, the curve equation implies
      # x² = (y² - 1) / (d y² + 1) (mod p).  The denominator is always
      # non-zero mod p.  Let u = y² - 1 and v = d y² + 1.
      y2 = Noble::Ed25519.mod(y * y)
      u = Noble::Ed25519.mod(y2 - One)
      v = Noble::Ed25519.mod(Curve::D * y2 + One)
      pair = Noble::Ed25519.uvRatio(u, v)
      isValid = pair[:isValid]
      x = pair[:value]
      raise Exception.new("Point.fromHex: invalid y coordinate") unless isValid

      # 4.  Finally, use the x_0 bit to select the right square root.  If
      # x = 0, and x_0 = 1, decoding fails.  Otherwise, if x_0 != x mod
      # 2, set x <-- p - x.  Return the decoded point (x,y).
      isXOdd = (x & One) == One
      isLastByteOdd = (hex_bytes[31] & 0x80) != 0
      if isLastByteOdd != isXOdd
        x = Noble::Ed25519.mod(-x)
      end

      Point.new(x, y)
    end

    def self.fromPrivateKey(privateKey : PrivKey)
      getExtendedPublicKey(privateKey).point
    end

    # There can always be only two x values (x, -x) for any y
    # When compressing point, it's enough to only store its y coordinate
    # and use the last byte to encode sign of x.
    def toRawBytes() : Bytes
      bytes = Noble::Ed25519.numberTo32BytesLE(@y)
      bytes[31] |= (@x & One == One ? 0x80 : 0)
      bytes
    end

    # Same as toRawBytes, but returns string.
    def toHex() : String
      Noble::Ed25519.bytesToHex(self.toRawBytes())
    end

    #**
    # Converts to Montgomery aka x coordinate of curve25519.
    # We don't have fromX25519, because we don't know sign.
    #
    # ```
    # u, v: curve25519 coordinates
    # x, y: ed25519 coordinates
    # (u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)
    # (x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))
    # ```
    # https://blog.filippo.io/using-ed25519-keys-for-encryption
    # @returns u coordinate of curve25519 point
    #/
    def toX25519() : Bytes
      u = Noble::Ed25519.mod((One + @y) * Noble::Ed25519.invert(One - @y))
      return Noble::Ed25519.numberTo32BytesLE(u)
    end

    def isTorsionFree() : Bool
      return ExtendedPoint.fromAffine(self).isTorsionFree()
    end

    def equals(other : Point) : Bool
      return @x === other.x && @y === other.y
    end

    def ==(other : Point) : Bool
      equals(other)
    end

    def negate()
      return Point.new(Noble::Ed25519.mod(-@x), @y)
    end

    def add(other : Point)
      return ExtendedPoint.fromAffine(self).add(ExtendedPoint.fromAffine(other)).toAffine()
    end

    def subtract(other : Point)
      return self.add(other.negate())
    end

    #**
    # Constant time multiplication.
    # @param scalar Big-Endian number
    # @returns new point
    #/
    def multiply(scalar : Int) : Point
      ExtendedPoint.fromAffine(self).multiply(scalar, self).toAffine()
    end
  end

  #**
  # EDDSA signature.
  #/
  class Signature
    property r : Point
    property s : BigInt

    def initialize(@r : Point, @s : BigInt)
      self.assertValidity()
    end

    def self.fromHex(hex : Hex) : Signature
      bytes = Noble::Ed25519.ensureBytes(hex, 64)
      r = Point.fromHex(bytes[0, 32], false)
      s = Noble::Ed25519.bytesToNumberLE(bytes[32, 32])
      Signature.new(r, s)
    end

    def assertValidity()
      # 0 <= s < l
      Noble::Ed25519.normalizeScalar(@s, Curve::L, false)
      self
    end

    def toRawBytes()
      u8 = Bytes.new(64)
      @r.toRawBytes().copy_to(u8)
      Noble::Ed25519.numberTo32BytesLE(self.s).each_with_index {|elem, i| u8[32 + i] = elem}
      u8
    end

    def toHex()
      bytesToHex(self.toRawBytes())
    end
  end

  # export { ExtendedPoint, RistrettoPoint, Point, Signature }

  def concatBytes(*arrays) : Bytes
    if arrays.size == 1
      arrays[0]
    else
      length = arrays.reduce(0) {|a, arr| a + arr.size }
      result = Bytes.new(length)
      i = 0
      pad = 0
      arrays.each do |arr|
        arr.each_with_index {|elem, j| result[pad + j] = elem }
        # result.set(arr, pad)
        pad += arr.size
      end
      result
    end
  end

  # Convert between types
  # ---------------------
  Hexes = (0..255).each.with_index.map {|v, i| i.to_s(16).rjust(2, '0') }.to_a
  def bytesToHex(uint8a : Bytes) : String
    # pre-caching improves the speed 6x
    hex = ""
    i = 0
    while i < uint8a.size  # for (i = 0 i < uint8a.length i++)
      hex += Hexes[uint8a[i]]
      i += 1
    end
    return hex
  end

  # Caching slows it down 2-3x
  def hexToBytes(hex : String) : Bytes
    raise Exception.new("hexToBytes: received invalid unpadded hex") unless hex.size % 2 == 0
    array = Bytes.new(hex.size // 2)
    i = 0
    while i < array.size   # for (i = 0 i < array.length i++)
      j = i * 2
      hexByte = hex[j, 2]
      byte = hexByte.to_u8(16)
      array[i] = byte
      i += 1
    end
    return array
  end

  def numberTo32BytesBE(num : BigInt) : Bytes
    length = 32
    hex = num.to_s(16).rjust(length * 2, '0')
    hexToBytes(hex)
  end

  def numberTo32BytesLE(num : BigInt) : Bytes
    numberTo32BytesBE(num).reverse!
  end

  # Little-endian check for first LE bit (last BE bit)
  def edIsNegative(num : BigInt)
    (mod(num) & One) === One
  end

  # Little Endian
  def bytesToNumberLE(uint8a : Bytes) : BigInt
    # BigInt.new("0x" + bytesToHex(uint8a.clone.reverse!))
    BigInt.from_bytes(uint8a)
  end

  def bytes255ToNumberLE(bytes : Bytes) : BigInt
    Noble::Ed25519.mod(bytesToNumberLE(bytes) & (Noble::Ed25519::Two ** BigInt256 - One))
  end
  # -------------------------

  def mod(a : BigInt, b : BigInt = Curve::P) : BigInt
    res = a % b
    res >= Zero ? res : b + res
  end

  # Note: this egcd-based invert is 50% faster than powMod-based one.
  # Inverses number over modulo
  def invert(number : BigInt, modulo : BigInt = Curve::P) : BigInt
    raise ArgumentError.new("invert: expected positive integers, got n=#{number} mod=#{modulo}") if number === Zero || modulo <= Zero
    # Eucledian GCD https://brilliant.org/wiki/extended-euclidean-algorithm/
    a = mod(number, modulo)
    b = modulo
    # prettier-ignore
    x = Zero
    y = One
    u = One
    v = Zero
    while a != Zero
      q = b // a
      r = b % a
      m = x - u * q
      n = y - v * q
      # prettier-ignore
      b = a
      a = r
      x = u
      y = v
      u = m
      v = n
    end
    gcd = b
    raise Exception.new("invert: does not exist") if gcd != One
    mod(x, modulo)
  end

  #**
  # Takes a list of numbers, efficiently inverts all of them.
  # @param nums list of BigInts
  # @param p modulo
  # @returns list of inverted BigInts
  # @example
  # Noble::Ed25519.invertBatch([1n, 2n, 4n], 21n)
  # # => [1n, 11n, 16n]
  #/
  def invertBatch(nums : Array(BigInt), p : BigInt = Curve::P) : Array(BigInt)
    # puts "size = #{nums.size}"
    tmp = Array(BigInt).new(nums.size, Noble::Ed25519::Zero)
    # Walk from first to last, multiply them by each other MOD p
    lastMultiplied = nums.each_with_index.reduce(One) do |acc, pair|
      num, i = pair
      next acc if num == Zero
      # puts "#{i} -> #{acc}"
      tmp[i] = acc
      Noble::Ed25519.mod(acc * num, p)
    end
    # Invert last element
    inverted = invert(lastMultiplied, p)
    # Walk from last to first, multiply them by inverted each other MOD p
    nums.fold_right(inverted) do |acc, num, i|
      # num, i = pair
      next acc if num == Zero
      tmp[i] = Noble::Ed25519.mod(acc * tmp[i], p)
      Noble::Ed25519.mod(acc * num, p)
    end
    return tmp
  end

  # Does x ^ (2 ^ power) mod p. pow2(30, 4) == 30 ^ (2 ^ 4)
  def pow2(x : BigInt, power : BigInt) : BigInt
    res = x
    while power > Zero
      power -= 1
      res *= res
      res %= Curve::P
    end
    return res
  end

  # Power to (p-5)/8 aka x^(2^252-3)
  # Used to calculate y - the square root of y².
  # Exponentiates it to very big number.
  # We are unwrapping the loop because it's 2x faster.
  # (2n**252n-3n).toString(2) would produce bits [250x 1, 0, 1]
  # We are multiplying it bit-by-bit
  def pow_2_252_3(x : BigInt)
    _5n = BigInt.new(5)
    _10n = BigInt.new(10)
    _20n = BigInt.new(20)
    _40n = BigInt.new(40)
    _80n = BigInt.new(80)
    x2 = (x * x) % Curve::P
    b2 = (x2 * x) % Curve::P # x^3, 11
    b4 = (pow2(b2, Noble::Ed25519::Two) * b2) % Curve::P # x^15, 1111
    b5 = (pow2(b4, One) * x) % Curve::P # x^31
    b10 = (pow2(b5, _5n) * b5) % Curve::P
    b20 = (pow2(b10, _10n) * b10) % Curve::P
    b40 = (pow2(b20, _20n) * b20) % Curve::P
    b80 = (pow2(b40, _40n) * b40) % Curve::P
    b160 = (pow2(b80, _80n) * b80) % Curve::P
    b240 = (pow2(b160, _80n) * b80) % Curve::P
    b250 = (pow2(b240, _10n) * b10) % Curve::P
    pow_p_5_8 = (pow2(b250, Noble::Ed25519::Two) * x) % Curve::P
    # ^ To pow to (p+3)/8, multiply it by x.
    { pow_p_5_8, b2 }
  end

  # Ratio of u to v. Allows us to combine inversion and square root. Uses algo from RFC8032 5.1.3.
  # Constant-time
  # prettier-ignore
  def uvRatio(u : BigInt, v : BigInt) : {isValid: Bool, value: BigInt}
    v3 = Noble::Ed25519.mod(v * v * v)                  # v³
    v7 = Noble::Ed25519.mod(v3 * v3 * v)                # v⁷
    pow, _ = pow_2_252_3(u * v7)
    x = Noble::Ed25519.mod(u * v3 * pow)                  # (uv³)(uv⁷)^(p-5)/8
    vx2 = Noble::Ed25519.mod(v * x * x)                 # vx²
    root1 = x                            # First root candidate
    root2 = Noble::Ed25519.mod(x * SQRT_M1)             # Second root candidate
    useRoot1 = vx2 == u                 # If vx² = u (mod p), x is a square root
    useRoot2 = vx2 == Noble::Ed25519.mod(-u)           # If vx² = -u, set x <-- x * 2^((p-1)/4)
    noRoot = vx2 == Noble::Ed25519.mod(-u * SQRT_M1)   # There is no valid root, vx² = -u√(-1)
    x = root1 if useRoot1
    x = root2 if useRoot2 || noRoot         # We return root2 anyway, for const-time
    x = Noble::Ed25519.mod(-x) if edIsNegative(x)
    {isValid: useRoot1 || useRoot2, value: x}
  end

  # Calculates 1/√(number)
  def invertSqrt(number : BigInt)
    uvRatio(One, number)
  end
  # Math end

  # Little-endian SHA512 with modulo n
  def sha512ModqLE(*args) : BigInt
    hash = Utils.sha512(concatBytes(*args))
    value = bytesToNumberLE(hash)
    Noble::Ed25519.mod(value, Curve::L)
  end

  def equalBytes(b1 : Bytes, b2 : Bytes)
    b1 == b2
  end

  def ensureBytes(hex : Hex, expectedLength : Int32? = nil) : Bytes
    # Bytes.from() instead of hash.slice() because node.js Buffer
    # is instance of Bytes, and its slice() creates **mutable** copy
    bytes = case hex
    in Bytes
      hex
    in String
      hexToBytes(hex)
    end
    # bytes = hex instanceof Bytes ? Bytes.from(hex) : hexToBytes(hex)
    raise Exception.new("Expected #{expectedLength} bytes") if expectedLength && bytes.size != expectedLength
      
    return bytes
  end

  #**
  # Checks for num to be in range:
  # For strict == true:  `0 <  num < max`.
  # For strict == false: `0 <= num < max`.
  # Converts non-float safe numbers to BigInts.
  #/
  def Noble::Ed25519.normalizeScalar(num : Int, max : BigInt, strict = true) : BigInt
    raise ArgumentError.new("Specify max value") unless max > 0
    # num = BigInt.new(num)
    case
    when strict && Zero < num && num < max
      num.to_big_i
    when !strict && Zero <= num && num < max
      num.to_big_i
    else
      raise ArgumentError.new("Expected valid scalar: 0 < scalar < max")
    end
    # if num < max
    #   if strict
    #     if (Zero < num) return num
    #   else
    #     if (Zero <= num) return num
    #   end
    # end
    # raise TypeException.new("Expected valid scalar: 0 < scalar < max")
  end

  def adjustBytes25519(bytes : Bytes) : Bytes
    # Section 5: For X25519, in order to decode 32 random bytes as an integer scalar,
    # set the three least significant bits of the first byte
    bytes[0] &= 248 # 0b1111_1000
    # and the most significant bit of the last to zero,
    bytes[31] &= 127 # 0b0111_1111
    # set the second most significant bit of the last byte to 1
    bytes[31] |= 64 # 0b0100_0000
    return bytes
  end

  def decodeScalar25519(n : Hex) : BigInt
    # and, finally, decode as little-endian.
    # This means that the resulting integer is of the form 2 ^ 254 plus eight times a value between 0 and 2 ^ 251 - 1(inclusive).
    bytesToNumberLE(adjustBytes25519(ensureBytes(n, 32)))
  end

  # Private convenience method
  # RFC8032 5.1.5
  def getExtendedPublicKey(key : PrivKey)
    # Normalize BigInt / number / string to Bytes
    key_bytes = case key
    in Hex
      ensureBytes(key)
    in Int
      numberTo32BytesBE(Noble::Ed25519.normalizeScalar(key, MAX_256B))
    end
    # key =
    #   typeof key === "BigInt" || typeof key === "number"
    #     ? numberTo32BytesBE(Noble::Ed25519.normalizeScalar(key, MAX_256B))
    #     : ensureBytes(key)
    raise Exception.new("Expected 32 bytes. Key is only #{key_bytes.size} bytes") unless key_bytes.size == 32
    # hash to produce 64 bytes
    hashed = Utils.sha512(key_bytes)
    # First 32 bytes of 64b uniformingly random input are taken,
    # clears 3 bits of it to produce a random field element.
    head = adjustBytes25519(hashed[0, 32])
    # Second 32 bytes is called key prefix (5.1.6)
    prefix = hashed[32, 32]
    # The actual private scalar
    scalar = Noble::Ed25519.mod(bytesToNumberLE(head), Curve::L)
    # Point on Edwards curve aka public key
    point = Point::BASE.multiply(scalar)
    pointBytes = point.toRawBytes()
    { head, prefix, scalar, point, pointBytes }
  end

  #**
  # Calculates ed25519 public key.
  # 1. private key is hashed with sha512, then first 32 bytes are taken from the hash
  # 2. 3 least significant bits of the first byte are cleared
  # RFC8032 5.1.5
  #/
  def getPublicKey(privateKey : PrivKey) : Bytes
    _, _, _, _, pointBytes = getExtendedPublicKey(privateKey)
    pointBytes
  end

  #**
  # Signs message with privateKey.
  # RFC8032 5.1.6
  #/
  def sign(message : Hex, privateKey : Hex) : Bytes
    message = ensureBytes(message)
    _, prefix, scalar, _, pointBytes = getExtendedPublicKey(privateKey)
    r = sha512ModqLE(prefix, message) # r = hash(prefix + msg)
    r_ = Point::BASE.multiply(r) # R = rG
    k = sha512ModqLE(r_.toRawBytes(), pointBytes, message) # k = hash(R + P + msg)
    s = Noble::Ed25519.mod(r + k * scalar, Curve::L) # s = r + kp
    return Signature.new(r_, s).toRawBytes()
  end

  #**
  # Verifies ed25519 signature against message and public key.
  # An extended group equation is checked.
  # RFC8032 5.1.7
  # Compliant with ZIP215:
  # 0 <= sig.R/publicKey < 2**256 (can be >= curve.P)
  # 0 <= sig.s < l
  # Not compliant with RFC8032: it's not possible to comply to both ZIP & RFC at the same time.
  #/
  def verify(sig : SigType, message : Hex, publicKey : PubKey) : Bool
    message = ensureBytes(message)
    # When hex is passed, we check public key fully.
    # When Point instance is passed, we assume it has already been checked, for performance.
    # If user passes Point/Sig instance, we assume it has been already verified.
    # We don't check its equations for performance. We do check for valid bounds for s though
    # We always check for: a) s bounds. b) hex validity
    
    # if (!(publicKey instanceof Point)) publicKey = Point.fromHex(publicKey, false)
    point = case publicKey
    in Hex
      Point.fromHex(publicKey, false)
    in Point
      publicKey
    end

    # { r, s } = sig instanceof Signature ? sig.assertValidity() : Signature.fromHex(sig)
    signature = case sig
    in Signature
      sig.assertValidity()
    in Hex
      Signature.fromHex(sig)
    end
    sb = ExtendedPoint::BASE.multiplyUnsafe(signature.s)
    k = sha512ModqLE(signature.r.toRawBytes(), point.toRawBytes(), message)
    kA = ExtendedPoint.fromAffine(point).multiplyUnsafe(k)
    rkA = ExtendedPoint.fromAffine(signature.r).add(kA)
    # [8][S]B = [8]R + [8][k]A'
    return rkA.subtract(sb).multiplyUnsafe(Curve::H).equals(ExtendedPoint::ZERO)
  end

  #**
  # Calculates X25519 DH shared secret from ed25519 private & public keys.
  # Curve25519 used in X25519 consumes private keys as-is, while ed25519 hashes them with sha512.
  # Which means we will need to normalize ed25519 seeds to "hashed repr".
  # @param privateKey ed25519 private key
  # @param publicKey ed25519 public key
  # @returns X25519 shared key
  #/
  def getSharedSecret(privateKey : PrivKey, publicKey : Hex) : Bytes
    head, _, _, _, _ = getExtendedPublicKey(privateKey)
    u = Point.fromHex(publicKey).toX25519()
    Curve25519.scalarMult(head, u)
  end

  # Enable precomputes. Slows down first publicKey computation by 20ms.
  Point::BASE._setWindowSize(8)

  # curve25519-related code
  # Curve equation: v^2 = u^3 + A*u^2 + u
  # https://datatracker.ietf.org/doc/html/rfc7748

  # cswap from RFC7748
  def cswap(swap : BigInt, x_2 : BigInt, x_3 : BigInt) : {BigInt, BigInt}
    dummy = Noble::Ed25519.mod(swap * (x_2 - x_3))
    x_2 = Noble::Ed25519.mod(x_2 - dummy)
    x_3 = Noble::Ed25519.mod(x_3 + dummy)
    {x_2, x_3}
  end

  # x25519 from 4
  #**
  #
  # @param pointU u coordinate (x) on Montgomery Curve 25519
  # @param scalar by which the point would be multiplied
  # @returns new Point on Montgomery curve
  #/
  def montgomeryLadder(pointU : BigInt, scalar : BigInt) : BigInt
    u = Noble::Ed25519.normalizeScalar(pointU, Curve::P)
    # Section 5: Implementations MUST accept non-canonical values and process them as
    # if they had been reduced modulo the field prime.
    k = Noble::Ed25519.normalizeScalar(scalar, Curve::P)
    # The constant a24 is (486662 - 2) / 4 = 121665 for curve25519/X25519
    a24 = BigInt.new(121665)
    x_1 = u
    x_2 = One
    z_2 = Zero
    x_3 = u
    z_3 = One
    swap = Zero
    sw : {BigInt, BigInt} = {BigInt.new(0), BigInt.new(0)}
    t = BigInt.new(255 - 1)
    while t >= Zero  # for (t = BigInt.new(255 - 1) t >= Zero t--) {
      k_t = (k >> t) & One
      swap ^= k_t
      sw = cswap(swap, x_2, x_3)
      x_2 = sw[0]
      x_3 = sw[1]
      sw = cswap(swap, z_2, z_3)
      z_2 = sw[0]
      z_3 = sw[1]
      swap = k_t

      a_ = x_2 + z_2
      aa_ = Noble::Ed25519.mod(a_ * a_)
      b_ = x_2 - z_2
      bb_ = Noble::Ed25519.mod(b_ * b_)
      e_ = aa_ - bb_
      c_ = x_3 + z_3
      d_ = x_3 - z_3
      da_ = Noble::Ed25519.mod(d_ * a_)
      cb_ = Noble::Ed25519.mod(c_ * b_)
      x_3 = Noble::Ed25519.mod((da_ + cb_) ** Noble::Ed25519::Two)
      z_3 = Noble::Ed25519.mod(x_1 * (da_ - cb_) ** Noble::Ed25519::Two)
      x_2 = Noble::Ed25519.mod(aa_ * bb_)
      z_2 = Noble::Ed25519.mod(e_ * (aa_ + Noble::Ed25519.mod(a24 * e_)))
      t -= 1
    end
    sw = cswap(swap, x_2, x_3)
    x_2 = sw[0]
    x_3 = sw[1]
    sw = cswap(swap, z_2, z_3)
    z_2 = sw[0]
    z_3 = sw[1]
    pow_p_5_8, b2 = pow_2_252_3(z_2)
    # x^(p-2) aka x^(2^255-21)
    xp2 = Noble::Ed25519.mod(pow2(pow_p_5_8, BigInt.new(3)) * b2)
    Noble::Ed25519.mod(x_2 * xp2)
  end

  def encodeUCoordinate(u : BigInt) : Bytes
    numberTo32BytesLE(Noble::Ed25519.mod(u, Curve::P))
  end

  def decodeUCoordinate(uEnc : Hex) : BigInt
    u = ensureBytes(uEnc, 32)
    # Section 5: When receiving such an array, implementations of X25519
    # MUST mask the most significant bit in the final byte.
    u[31] &= 127 # 0b0111_1111
    bytesToNumberLE(u)
  end

  module Curve25519
    BASE_POINT_U = "0900000000000000000000000000000000000000000000000000000000000000"

    # crypto_scalarmult aka getSharedSecret
    def self.scalarMult(privateKey : Hex, publicKey : Hex) : Bytes
      u = Noble::Ed25519.decodeUCoordinate(publicKey)
      p = Noble::Ed25519.decodeScalar25519(privateKey)
      pu = Noble::Ed25519.montgomeryLadder(u, p)
      # The result was not contributory
      # https://cr.yp.to/ecdh.html#validate
      raise Exception.new("Invalid private or public key received") if pu == Zero
      Noble::Ed25519.encodeUCoordinate(pu)
    end

    # crypto_scalarmult_base aka getPublicKey
    def self.scalarMultBase(privateKey : Hex) : Bytes
      scalarMult(privateKey, BASE_POINT_U)
    end
  end

  # Global symbol available in browsers only. Ensure we do not depend on @types/dom
  # declare self : Record<string, any> | undefined
  # crypto : { node? : any, web? : any } = {
  #   node: nodeCrypto,
  #   web: typeof self === "object" && "crypto" in self ? self.crypto : undefined,
  # }

  module Utils
    extend self

    # The 8-torsion subgroup ℰ8.
    # Those are "buggy" points, if you multiply them by 8, you'll receive Point::ZERO.
    # Ported from curve25519-dalek.
    TORSION_SUBGROUP = [
      "0100000000000000000000000000000000000000000000000000000000000000",
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
      "0000000000000000000000000000000000000000000000000000000000000080",
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    ] of String

    # bytesToHex,
    # getExtendedPublicKey,
    # mod,
    # invert,

    #**
    # Can take 40 or more bytes of uniform input e.g. from CSPRNG or KDF
    # and convert them into private scalar, with the modulo bias being neglible.
    # As per FIPS 186 B.1.1.
    # @param hash hash output from sha512, or a similar function
    # @returns valid private scalar
    #/
    def hashToPrivateScalar(hash : Hex) : BigInt
      hash = ensureBytes(hash)
      raise Exception.new("Expected 40-1024 bytes of private key as per FIPS 186") if hash.size < 40 || hash.size > 1024
      num = Noble::Ed25519.mod(bytesToNumberLE(hash), Curve::L)
      # This should never happen
      raise Exception.new("Invalid private key") if num === Zero || num === One
      num
    end

    def randomBytes(bytesLength : Int = 32) : Bytes
      Random::Secure.random_bytes(bytesLength)
    end

    # Note: ed25519 private keys are uniform 32-bit strings. We do not need
    # to check for modulo bias like we do in noble-secp256k1 randomPrivateKey()
    def randomPrivateKey() : Bytes
      randomBytes(32)
    end

    def sha512(message : Bytes) : Bytes
      Digest::SHA512.digest(message)
    end
    #
    # We're doing scalar multiplication (used in getPublicKey etc) with precomputed BASE_POINT
    # values. This slows down first getPublicKey() by milliseconds (see Speed section),
    # but allows to speed-up subsequent getPublicKey() calls up to 20x.
    # @param windowSize 2, 4, 8, 16
    #
    def precompute(windowSize = 8, point = Point::BASE) : Point
      cached = point.equals(Point::BASE) ? point : Point.new(point.x, point.y)
      cached._setWindowSize(windowSize)
      cached.multiply(Noble::Ed25519::Two)
      cached
    end
  end
end
