module EventMachine

  module SSL

    module X509

      # This class wraps some of the data available from an X509_STORE_CTX
      # object.
      #
      # @see Connection#ssl_verify_peer
      class StoreContext

        def initialize(current_cert, error_depth, error, error_string)
          require "openssl"
          @current_cert = OpenSSL::X509::Certificate.new(current_cert)
          @error = error
          @error_depth = error_depth
          @error_string = error_string
          freeze
        end

        # @return [OpenSSL::X509::Certificate] the certificate in this context
        attr_reader :current_cert

        # @return [Integer] the error code of this context.
        #
        # See "ERROR CODES" in the X509_STORE_CTX_GET_ERROR(3SSL) man page for a
        # full description of all error codes.
        #
        # @note The "error" is also used for non-errors, i.e. X509_V_OK.
        attr_reader :error

        # @return [Integer] the depth of the error
        #
        # This is a nonnegative integer representing where in the certificate
        # chain the error occurred. If it is zero it occurred in the end entity
        # certificate, one if it is the certificate which signed the end entity
        # certificate and so on.
        #
        # @note The "error" depth is also used for non-errors, i.e. X509_V_OK.
        attr_reader :error_depth

        # @return [String] human readable error string for verification {error}
        #
        # @note The "error" string can be "ok", i.e. no error.
        attr_reader :error_string

      end

    end

    # SSLContext is used to set various options regarding certificates,
    # algorithms, verification, session caching, etc.  The SSL::SSLContext is
    # used by {Connection#start_tls} to create an internal SSL_CTX object.
    #
    # All parameters must be set before using with {Connection#start_tls},
    # as the SSLContext will be frozen afterward.
    #
    # This class partially duplicates stdlib's SSLContext class--much of its
    # code was copied directly from the openssl gem.  It does *not* (currently)
    # represent an underlying SSL_CTX object which can be shared, nor can it
    # handle all of the SSL_CTX parameters supported by the openssl gem.  It is
    # used internally to configure new SSL_CTX objects.
    class SSLContext

      # call-seq:
      #    Context.new           -> ctx
      #    Context.new(:TLSv1)   -> ctx
      #    Context.new("SSLv23") -> ctx
      #
      # Creates a new SSL context.
      #
      # If an argument is given, #ssl_version= is called with the value.
      def initialize(version = nil)
        @setup_done = false
        self.ssl_version = version if version
      end

      attr_accessor :verify_peer
      attr_accessor :cipher_list
      attr_accessor :ssl_version
      attr_accessor :ecdh_curve
      attr_accessor :dhparam
      attr_accessor :fail_if_no_peer_cert

      # @return [String] the client certificate to use, complete with header and
      #   footer. If a cert chain is required, you should use the
      #   {cert_chain_file} option. If both {cert_chain_file} and {cert} are
      #   used, BadCertParams will be raised.
      attr_accessor :cert

      # @return [String] a string, complete with header
      #   and footer, that must contain a private key in the [PEM
      #   format](http://en.wikipedia.org/wiki/Privacy_Enhanced_Mail). If both
      #   :private_key_file and :private_key are used, BadPrivateKeyParams will be
      #   raised. If the Private Key does not match the certificate,
      #   InvalidPrivateKey will be raised.
      #
      # @todo copy add_certificate from stdlib and deprecate this
      attr_accessor :key
      alias private_key= key=
      alias private_key  key

      # @return [String] local path of a readable file that contants a chain of
      #   X509 certificates in the [PEM
      #   format](http://en.wikipedia.org/wiki/Privacy_Enhanced_Mail), with the
      #   most-resolved certificate at the top of the file, successive
      #   intermediate certs in the middle, and the root (or CA) cert at the
      #   bottom. If both :cert_chain_file and :cert are used, BadCertParams
      #   will be raised.
      attr_accessor :cert_chain_file

      # @return [String] local path of a readable file that must contain a
      #   private key in the [PEM
      #   format](http://en.wikipedia.org/wiki/Privacy_Enhanced_Mail). If both
      #   :private_key_file and :private_key are used, BadPrivateKeyParams will
      #   be raised. If the Private Key does not match the certificate,
      #   InvalidPrivateKey will be raised.
      attr_accessor :private_key_file

      # @return [String] :private_key_pass (nil) a string to use as password
      #   to decode :private_key or :private_key_file
      attr_accessor :private_key_pass

      # @return [String] The local path of a file containing DH parameters for
      #   EDH ciphers in [PEM
      #   format](http://en.wikipedia.org/wiki/Privacy_Enhanced_Mail) See:
      #   'openssl dhparam'
      attr_accessor :dhparam

      # @param curves [String] The curve for ECDHE ciphers. See available
      #   ciphers with 'openssl ecparam -list_curves'
      attr_accessor :ecdh_curves

      # @deprecated Provided for backwards compatibility.  Use {#ecdh_curves}.
      alias :ecdh_curve  :ecdh_curves
      # @deprecated Provided for backwards compatibility.  Use {#ecdh_curves=}.
      alias :ecdh_curve= :ecdh_curves=

      # Prepares this context to be used, and also freezes it.
      def freeze
        setup
        super
      end

      # Prepares this context to be used, and also freezes it.
      def setup
        return if @setup_done
        guard_cert_options!
        @setup_done = true
        freeze
      end

      # @private
      def em_tls_parms(sni_hostname:)
        raise "call #setup before #em_tls_parms" unless @setup_done
        [
          private_key_file      || '',
          private_key           || '',
          private_key_pass      || '',
          cert_chain_file       || '',
          cert                  || '',
          verify_peer,
          fail_if_no_peer_cert,
          sni_hostname          || '',
          cipher_list           || '',
          ecdh_curve            || '',
          dhparam               || '',
          protocols_bitmask,
        ]
      end

      private

      def guard_cert_options!
        [private_key_file, cert_chain_file].each do |file|
          next unless tls_parm_set?(file)
          raise FileNotFoundException,
            "Could not find #{file} for #{self.class}" unless File.exist? file
        end

        if tls_parm_set?(private_key_file) && tls_parm_set?(private_key)
          raise BadPrivateKeyParams,
            "Specifying both private_key and private_key_file not allowed"
        end

        if tls_parm_set?(cert_chain_file) && tls_parm_set?(cert)
          raise BadCertParams,
            "Specifying both cert and cert_chain_file not allowed"
        end

        if tls_parm_set?(private_key_file) || tls_parm_set?(private_key)
          if !tls_parm_set?(cert_chain_file) && !tls_parm_set?(cert)
            raise BadParams,
              "You have specified a private key to use, but not the related cert"
          end
        end
      end

      def tls_parm_set?(parm)
        !(parm.nil? || parm.empty?)
      end

      def protocols_bitmask
        protocols_bitmask = 0
        if ssl_version.nil?
          protocols_bitmask |= EventMachine::EM_PROTO_TLSv1
          protocols_bitmask |= EventMachine::EM_PROTO_TLSv1_1
          protocols_bitmask |= EventMachine::EM_PROTO_TLSv1_2
          if EventMachine.const_defined? :EM_PROTO_TLSv1_3
            protocols_bitmask |= EventMachine::EM_PROTO_TLSv1_3
          end
        else
          [ssl_version].flatten.each do |p|
            case p.to_s.downcase
            when 'sslv2'
              protocols_bitmask |= EventMachine::EM_PROTO_SSLv2
            when 'sslv3'
              protocols_bitmask |= EventMachine::EM_PROTO_SSLv3
            when 'tlsv1'
              protocols_bitmask |= EventMachine::EM_PROTO_TLSv1
            when 'tlsv1_1'
              protocols_bitmask |= EventMachine::EM_PROTO_TLSv1_1
            when 'tlsv1_2'
              protocols_bitmask |= EventMachine::EM_PROTO_TLSv1_2
            when 'tlsv1_3'
              protocols_bitmask |= EventMachine::EM_PROTO_TLSv1_3
            else
              raise("Unrecognized SSL/TLS Protocol: #{p}")
            end
          end
        end
        protocols_bitmask
      end

    end

  end
end
