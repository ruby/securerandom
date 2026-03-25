# This file is only for RDoc

# Random provides an interface to Ruby's pseudo-random number generator, or
# PRNG.
#
# See also Random::Formatter module that adds convenience methods to generate
# various forms of random data.
require 'securerandom'
require 'openssl'

module Random
  def self.bytes(n)
    OpenSSL::Random.random_bytes(10)
  end
end
