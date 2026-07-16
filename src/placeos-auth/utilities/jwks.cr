require "base64"
require "digest/sha256"

module PlaceOS::Auth
  # Builds the JWKS document served at `/auth/oauth/discovery/keys`
  # (PPT-2536), matching what doorkeeper-openid_connect derived from the
  # same RSA signing key on the legacy service.
  #
  # The RSA public parameters (n, e) are extracted by walking the PEM's
  # DER structure directly — the OpenSSL bindings in our dependency tree
  # don't expose `RSA_get0_key`, and the structures involved are small
  # and fixed. Both public-key PEM flavours are handled:
  #
  #   "BEGIN PUBLIC KEY" (SubjectPublicKeyInfo):
  #     SEQUENCE
  #       SEQUENCE       -- AlgorithmIdentifier (rsaEncryption, NULL)
  #       BIT STRING     -- wraps the PKCS#1 structure below
  #   "BEGIN RSA PUBLIC KEY" (PKCS#1):
  #     SEQUENCE
  #       INTEGER n
  #       INTEGER e
  module JWKS
    extend self

    class ParseError < Error
    end

    struct Key
      include JSON::Serializable

      getter kty : String = "RSA"
      getter n : String
      getter e : String
      getter kid : String
      getter use : String = "sig"
      getter alg : String = "RS256"

      def initialize(@n, @e)
        # RFC 7638 thumbprint: SHA-256 over the canonical JSON of the
        # required members in lexicographic key order.
        thumbprint_input = %({"e":"#{@e}","kty":"RSA","n":"#{@n}"})
        @kid = Base64.urlsafe_encode(Digest::SHA256.digest(thumbprint_input), padding: false)
      end
    end

    def key_for(public_pem : String) : Key
      modulus, exponent = rsa_params(public_pem)
      Key.new(
        Base64.urlsafe_encode(modulus, padding: false),
        Base64.urlsafe_encode(exponent, padding: false),
      )
    end

    private def rsa_params(pem : String) : {Bytes, Bytes}
      der = Reader.new(pem_contents(pem))
      der.enter_sequence
      if pem.includes?("BEGIN RSA PUBLIC KEY")
        {der.read_integer, der.read_integer}
      else
        der.skip_element # AlgorithmIdentifier
        inner = Reader.new(der.read_bit_string)
        inner.enter_sequence
        {inner.read_integer, inner.read_integer}
      end
    end

    private def pem_contents(pem : String) : Bytes
      base64 = pem.lines.reject(&.starts_with?("-----")).join
      raise ParseError.new("empty PEM") if base64.empty?
      Base64.decode(base64)
    end

    # Minimal DER tag-length-value reader for the fixed structures above.
    private class Reader
      def initialize(@bytes : Bytes)
        @pos = 0
      end

      def enter_sequence : Nil
        tag, _length = read_header
        raise ParseError.new("expected SEQUENCE, got 0x#{tag.to_s(16)}") unless tag == 0x30_u8
        # position now sits on the first child element
      end

      def skip_element : Nil
        _tag, length = read_header
        advance length
      end

      # BIT STRING content minus the leading unused-bits count byte.
      def read_bit_string : Bytes
        tag, length = read_header
        raise ParseError.new("expected BIT STRING, got 0x#{tag.to_s(16)}") unless tag == 0x03_u8
        unused = @bytes[@pos]
        raise ParseError.new("unsupported BIT STRING padding") unless unused.zero?
        value = @bytes[@pos + 1, length - 1]
        advance length
        value
      end

      # INTEGER content with any DER sign-padding byte stripped.
      def read_integer : Bytes
        tag, length = read_header
        raise ParseError.new("expected INTEGER, got 0x#{tag.to_s(16)}") unless tag == 0x02_u8
        value = @bytes[@pos, length]
        advance length
        value = value[1..] if value.size > 1 && value[0].zero?
        value
      end

      private def read_header : {UInt8, Int32}
        tag = next_byte
        first = next_byte
        length = if first < 0x80_u8
                   first.to_i32
                 else
                   octets = (first & 0x7F_u8).to_i32
                   raise ParseError.new("unreasonable DER length") if octets.zero? || octets > 4
                   octets.times.reduce(0_i32) { |acc, _| (acc << 8) | next_byte.to_i32 }
                 end
        raise ParseError.new("DER length overruns buffer") if @pos + length > @bytes.size
        {tag, length}
      end

      private def next_byte : UInt8
        raise ParseError.new("unexpected end of DER") if @pos >= @bytes.size
        byte = @bytes[@pos]
        @pos += 1
        byte
      end

      private def advance(length : Int32) : Nil
        @pos += length
      end
    end
  end
end
