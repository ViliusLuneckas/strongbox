require 'openssl'
require 'base64'

require 'strongbox/version'
require 'strongbox/cipher'
require 'strongbox/lock'
require 'strongbox/encrypt_with_public_key'

module Strongbox
  RSA_PKCS1_PADDING      = OpenSSL::PKey::RSA::PKCS1_PADDING
  RSA_SSLV23_PADDING     = OpenSSL::PKey::RSA::SSLV23_PADDING
  RSA_NO_PADDING         = OpenSSL::PKey::RSA::NO_PADDING
  RSA_PKCS1_OAEP_PADDING = OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING

  class StrongboxError < StandardError; end

  class << self
    # Provides for setting the default options for Strongbox
    def options
      @options ||= {
        base64:                  false,
        symmetric:               :always,
        padding:                 RSA_PKCS1_PADDING,
        symmetric_cipher:        'aes-256-cbc',
        ensure_required_columns: true,
        deferred_encryption:     false
      }
    end
  end
end

if defined?(Rails)
  require 'strongbox/railtie'
elsif defined?(ActiveRecord)
  ActiveRecord::Base.send(:include, Strongbox::EncryptWithPublicKey)
end
