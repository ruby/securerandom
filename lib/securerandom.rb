# -*- coding: us-ascii -*-
# frozen_string_literal: true

require 'random/formatter'

# == Secure random number generator interface.
#
# This library is an interface to secure random number generators which are
# suitable for generating session keys in HTTP cookies, etc.
#
# You can use this library in your application by requiring it:
#
#   require 'securerandom'
#
# It supports the following secure random number generators:
#
# * openssl
# * /dev/urandom
# * Win32
#
# SecureRandom is extended by the Random::Formatter module which
# defines the following methods:
#
# * alphanumeric
# * base64
# * choose
# * gen_random
# * hex
# * rand
# * random_bytes
# * random_number
# * urlsafe_base64
# * uuid
#
# These methods are usable as class methods of SecureRandom such as
# +SecureRandom.hex+.
#
# If a secure random number generator is not available,
# +NotImplementedError+ is raised.

module SecureRandom

  # The version
  VERSION = "0.4.1"

  class << self
    # Returns a random binary string containing +size+ bytes.
    #
    # See Random.bytes
    def bytes(n)
      return gen_random(n)
    end

    # Compatibility methods for Ruby 3.2, we can remove this after dropping to support Ruby 3.2
    def alphanumeric(n = nil, chars: ALPHANUMERIC)
      n = 16 if n.nil?
      choose(chars, n)
    end if RUBY_VERSION < '3.3'

    # Compatibility methods for Ruby 3.1 and Ruby 3.2.
    if RUBY_VERSION < '3.3'
      # Generates a random version 4 UUID.
      def uuid_v4
        uuid
      end

      # Generates a random version 7 UUID using the current Unix timestamp.
      #
      # +extra_timestamp_bits+ specifies additional timestamp precision from
      # 0 to 12 bits.
      def uuid_v7(extra_timestamp_bits: 0)
        case (extra_timestamp_bits = Integer(extra_timestamp_bits))
        when 0
          ms = Process.clock_gettime(Process::CLOCK_REALTIME, :millisecond)
          random = random_bytes(10)
          random.setbyte(0, random.getbyte(0) & 0x0f | 0x70)
          random.setbyte(2, random.getbyte(2) & 0x3f | 0x80)
          "%08x-%04x-%s" % [
            (ms & 0x0000_ffff_ffff_0000) >> 16,
            (ms & 0x0000_0000_0000_ffff),
            random.unpack("H4H4H12").join("-")
          ]
        when 12
          ms, ns = Process.clock_gettime(Process::CLOCK_REALTIME, :nanosecond).divmod(1_000_000)
          extra_bits = ns * 4096 / 1_000_000
          random = random_bytes(8)
          random.setbyte(0, random.getbyte(0) & 0x3f | 0x80)
          "%08x-%04x-7%03x-%s" % [
            (ms & 0x0000_ffff_ffff_0000) >> 16,
            (ms & 0x0000_0000_0000_ffff),
            extra_bits,
            random.unpack("H4H12").join("-")
          ]
        when (0..12)
          rand_a, rand_b1, rand_b2, rand_b3 = random_bytes(10).unpack("nnnN")
          rand_mask_bits = 12 - extra_timestamp_bits
          ms, ns = Process.clock_gettime(Process::CLOCK_REALTIME, :nanosecond).divmod(1_000_000)
          "%08x-%04x-%04x-%04x-%04x%08x" % [
            (ms & 0x0000_ffff_ffff_0000) >> 16,
            (ms & 0x0000_0000_0000_ffff),
            0x7000 |
              ((ns * (1 << extra_timestamp_bits) / 1_000_000) << rand_mask_bits) |
              rand_a & ((1 << rand_mask_bits) - 1),
            0x8000 | (rand_b1 & 0x3fff),
            rand_b2,
            rand_b3
          ]
        else
          raise ArgumentError, "extra_timestamp_bits must be in 0..12"
        end
      end
    end

    private

    # :stopdoc:

    # Implementation using OpenSSL
    def gen_random_openssl(n)
      return OpenSSL::Random.random_bytes(n)
    end

    # Implementation using system random device
    def gen_random_urandom(n)
      ret = Random.urandom(n)
      unless ret
        raise NotImplementedError, "No random device"
      end
      unless ret.length == n
        raise NotImplementedError, "Unexpected partial read from random device: only #{ret.length} for #{n} bytes"
      end
      ret
    end

    begin
      # Check if Random.urandom is available
      Random.urandom(1)
      alias gen_random gen_random_urandom
    rescue RuntimeError
      begin
        require 'openssl'
      rescue NoMethodError
        raise NotImplementedError, "No random device"
      else
        alias gen_random gen_random_openssl
      end
    end

    # :startdoc:

    # Generate random data bytes for Random::Formatter
    public :gen_random
  end
end

SecureRandom.extend(Random::Formatter)
