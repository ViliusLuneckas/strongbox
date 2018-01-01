module Strongbox
  module EncryptWithPublicKey
    class << self
      def included base #:nodoc:
        base.extend ClassMethods
        base.class_attribute :lock_options
      end
    end

    module ClassMethods
      # +encrypt_with_public_key+ gives the class it is called on an attribute that
      # when assigned is automatically encrypted using a public key.  This allows the
      # unattended encryption of data, without exposing the information need to decrypt
      # it (as would be the case when using symmetric key encryption alone).  Small
      # amounts of data may be encrypted directly with the public key.  Larger data is
      # encrypted using symmetric encryption. The encrypted data is stored in the
      # database column of the same name as the attibute.  If symmetric encryption is
      # used (the default) additional column are need to store the generated password
      # and IV.
      #
      # Last argument should be the options hash
      # Argument 0..-2 contains columns to be encrypted
      def encrypt_with_public_key(*args)
        include InstanceMethods

        # options = args.extract_options! could be used?
        options = args.delete_at(-1) || {}

        unless options.is_a?(Hash)
          args.push(options)
          options = {}
        end

        args.each { |name| mount_lock(name, options) }
      end

      def mount_lock(name, options)
        self.lock_options ||= {}
        lock_options[name] = options.symbolize_keys.reverse_merge(Strongbox.options)

        define_method(name) do
          lock_for(name)
        end

        define_method("#{name}=") do |plaintext|
          lock_for(name).content(plaintext)
        end

        if lock_options[name][:deferred_encryption]
          before_save do
            lock_for(name).encrypt!
          end
        end
      end
    end

    module InstanceMethods
      def lock_for(name)
        @_locks       ||= {}
        @_locks[name] ||= Lock.new(name, self, self.class.lock_options[name])
      end
    end
  end
end
