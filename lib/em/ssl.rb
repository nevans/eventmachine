require "openssl"

module EventMachine

  module SSL

    # A placeholder class for future X509 certificate store functionality
    #
    # From OpenSSL's `X509_STORE_ADD_CERT(3SSL)` man page:
    # The X509_STORE structure is intended to be a consolidated mechanism for
    # holding information about X.509 certificates and CRLs, and constructing
    # and validating chains of certificates terminating in trusted roots.
    class X509Store

      # This represents the default EventMachine {X509_STORE}, which is not
      # identical to the X509_STORE used by the "openssl" gem, although they
      # should be configured identically.
      DEFAULT = new.freeze

      def self.new
        raise NotImplementedError, "EventMachine::SSL X509_STORE wrapper"
      end
    end

    # Context is used to set various options regarding certificates, algorithms,
    # verification, session caching, etc.  The SSL::Context is used by
    # {Connection#start_tls} to create an internal SSL_CTX object.
    #
    # All parameters must be set before using with {Connection#start_tls},
    # as the Context will be frozen afterward.
    #
    # This class partially duplicates stdlib's SSLContext class--much of its
    # code was copied directly from the openssl gem.  It does *not* (currently)
    # represent an underlying SSL_CTX object which can be shared, nor can it
    # handle all of the SSL_CTX parameters supported by the openssl gem.  It is
    # used internally to configure new SSL_CTX objects.
    #
    # @todo wrap an SSL_CTX or SslContext_t object with TypedData_Wrap_Struct
    # @todo support other parameters and callbacks in stdlib's SSLContext
    # @todo support passing an encryption parameter, which can be string or
    #   Proc, to get a passphrase for encrypted private keys.
    # @todo support passing key material via raw strings or Procs that return
    #   strings instead of just filenames.
    class Context
      DEFAULT_PARAMS = OpenSSL::SSL::SSLContext::DEFAULT_PARAMS
      DEFAULT_CERT_STORE = SSL::X509Store::DEFAULT

      # call-seq:
      #    Context.new           -> ctx
      #    Context.new(:TLSv1)   -> ctx
      #    Context.new("SSLv23") -> ctx
      #
      # Creates a new SSL context.
      #
      # If an argument is given, #ssl_version= is called with the value. Note
      # that this form is deprecated. New applications should use #min_version=
      # and #max_version= as necessary.
      def initialize(version = nil)
        super()
        self.options |= OpenSSL::SSL::OP_ALL
        self.ssl_version = version if version
        self.verify_mode = OpenSSL::SSL::VERIFY_NONE
        self.verify_hostname = false
      end

      #######################################################################
      # @!group Attributes which match the standard library's "openssl" gem

      # @return [String] The path to a file containing a PEM-format CA
      #   certificate
      attr_accessor :ca_file

      # @return [String] The path to a directory containing CA certificates in
      #   PEM format.
      #
      # Files are looked up by subject's X509 name's hash value.
      attr_accessor :ca_path

      # @return [X509Store] An X509 Store used for certificate verification.
      #
      # If {#ca_file}, {#ca_path}, and {#cert_store} are not set and
      # {#verify_mode} isn't {VERIFY_NONE}, then {#set_params} will set this to
      # {EventMachine::SSL::X509Store::DEFAULT}.
      #
      # Earlier versions of EventMachine left this unset, but that is *strongly*
      # discouraged.
      #
      # TODO: allow setting with a user-defined X509 Store object.
      attr_accessor :cert_store

      # @return [Integer] Session verification mode, as a bitmask.
      #
      # Valid modes are {VERIFY_NONE}, {VERIFY_PEER}, {VERIFY_CLIENT_ONCE},
      # {VERIFY_FAIL_IF_NO_PEER_CERT}, which are defined on {OpenSSL::SSL}.
      #
      # The default mode is VERIFY_NONE, which does not perform any verification
      # at all.  Calling {#set_params} will use {VERIFY_PEER} as a safer
      # default.
      #
      # See SSL_CTX_set_verify(3) for details.
      attr_accessor :verify_mode

      # @return [Boolean] Whether to check the server certificate is valid for
      #   the hostname.
      #
      # In order to make this work, {#verify_mode} must be set to {VERIFY_PEER}
      # and the server hostname must be provided to {Connection#start_tls}.
      attr_accessor :verify_hostname

      #######################################################################
      # @!group Methods copied from standard library's "openssl/ssl.rb"

      # call-seq:
      #   ctx.set_params(params = {}) -> params
      #
      # Sets saner defaults optimized for the use with HTTP-like protocols.
      #
      # If a Hash _params_ is given, the parameters are overridden with it.
      # The keys in _params_ must be assignment methods on Context.
      #
      # If the verify_mode is not VERIFY_NONE and ca_file, ca_path and
      # cert_store are not set then the system default certificate store is
      # used.
      def set_params(params={})
        params = DEFAULT_PARAMS.merge(params)
        self.options = params.delete(:options) # set before min_version/max_version
        params.each{|name, value| self.__send__("#{name}=", value) }
        if self.verify_mode != OpenSSL::SSL::VERIFY_NONE
          unless self.ca_file or self.ca_path or self.cert_store
            self.cert_store = DEFAULT_CERT_STORE
          end
        end
        return params
      end

      # Sets the lower bound of the supported SSL/TLS protocol version.
      #
      # @param [String, Symbol, Integer, nil] version may be
      #   specified by an integer constant named `OpenSSL::SSL::*_VERSION`, a
      #   Symbol or String, or `nil` which means "any version".
      #
      #   Symbols and Strings are case-insensitive and should
      #   match the named constants used by `OpenSSL::SSL::*_VERSION`.
      #
      #   For backwards compatibility, an optional `v` can be in the version
      #   name, e.g. `TLS1_3` vs `TLSv1_3`
      #
      # @note Be careful that you don't overwrite
      #   OpenSSL::SSL::OP_NO_{SSL,TLS}v* options by {#options=} once you have
      #   called {#min_version=} or {#max_version=}.
      #
      # @example
      #    ctx.min_version = OpenSSL::SSL::TLS1_2_VERSION
      #    ctx.min_version = :TLS1_2
      #    ctx.min_version = :TLSv1_2
      #    ctx.min_version = nil
      #
      # @example Initiate a connection using either TLS 1.1 or TLS 1.2
      #    ctx = EventMachine::SSL::Context.new
      #    ctx.set_params(
      #      min_version: OpenSSL::SSL::TLS1_1_VERSION,
      #      max_version: OpenSSL::SSL::TLS1_2_VERSION
      #    )
      #
      #    em_connection.start_tls(context: ctx)
      def min_version=(version)
        version = self.class.parse_proto_version(version)
        set_minmax_proto_version(version, @max_proto_version ||= nil)
        @min_proto_version = version
      end

      # Sets the upper bound of the supported SSL/TLS protocol version.
      #
      # @param (see #min_version=)
      # @note (see #min_version=)
      #
      # @example
      #    ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION
      #    ctx.max_version = :TLS1_2
      #    ctx.min_version = :TLSv1_2
      #    ctx.max_version = nil
      def max_version=(version)
        version = self.class.parse_proto_version(version)
        set_minmax_proto_version(@min_proto_version ||= nil, version)
        @max_proto_version = version
      end

      # @deprecated Only provided for backwards compatibility. Use #min_version=
      # and #max_version= instead.
      #
      # @param meth [Symbol, String] the protocol version
      #    ctx.ssl_version = :TLSv1
      #    ctx.ssl_version = "SSLv23"
      #
      # Sets the SSL/TLS protocol version for the context. This forces
      # connections to use only the specified protocol version.
      #
      # === History
      # As the name hints, this used to call the SSL_CTX_set_ssl_version()
      # function which sets the SSL method used for connections created from
      # the context. As of Ruby/OpenSSL 2.1, this accessor method is
      # implemented to call #min_version= and #max_version= instead.
      def ssl_version=(version)
        return em_set_ssl_versions(*version) if version.is_a?(Array)
        version = version.to_s if version.is_a?(Symbol)
        if /(?<type>_client|_server)\z/ =~ version
          version = $`
          if $VERBOSE
            warn "#{caller(1, 1)[0]}: method type #{type.inspect} is ignored"
          end
        end
        version = METHODS_MAP[version.intern] or
          raise ArgumentError, "unknown SSL method `%s'" % version
        set_minmax_proto_version(version, version)
        @min_proto_version = @max_proto_version = version
      end

      METHODS_MAP = {
        SSLv23: 0,
        SSLv2: OpenSSL::SSL::SSL2_VERSION,
        SSLv3: OpenSSL::SSL::SSL3_VERSION,
        TLSv1: OpenSSL::SSL::TLS1_VERSION,
        TLSv1_1: OpenSSL::SSL::TLS1_1_VERSION,
        TLSv1_2: OpenSSL::SSL::TLS1_2_VERSION,
      }.merge(
        defined?(OpenSSL::SSL::TLS1_3_VERSION) ? {
          TLSv1_3: OpenSSL::SSL::TLS1_3_VERSION,
        } : {}
      ).freeze
      private_constant :METHODS_MAP

      #######################################################################
      ## @!group Copied or re-implemented from stdlib's `ossl_ssl.c`

      # @return [Integer] A bitfield with various OpenSSL options.
      #
      # See {SSL_CTX_get_options} and {SSL_CTX_set_options}
      #
      # TODO: wrap SSL_CTX and copy ossl_sslctx_get_options
      attr_accessor :options

      # TODO: add_certificate          => ossl_sslctx_add_certificate

      # @note ciphers will transformed into a string in rubymain.cpp
      attr_accessor :ciphers

      # TODO: ecdh_curves              => ossl_sslctx_set_ecdh_curves

      PROTOS_MAP = METHODS_MAP.merge({
        ssl23:   0,
        sslv23:  0,
        ssl2:    OpenSSL::SSL::SSL2_VERSION,
        sslv2:   OpenSSL::SSL::SSL2_VERSION,
        ssl3:    OpenSSL::SSL::SSL3_VERSION,
        sslv3:   OpenSSL::SSL::SSL3_VERSION,
        tls1:    OpenSSL::SSL::TLS1_VERSION,
        tlsv1:   OpenSSL::SSL::TLS1_VERSION,
        tls1_1:  OpenSSL::SSL::TLS1_1_VERSION,
        tlsv1_1: OpenSSL::SSL::TLS1_1_VERSION,
        tls1_2:  OpenSSL::SSL::TLS1_2_VERSION,
        tlsv1_2: OpenSSL::SSL::TLS1_2_VERSION,
      }).merge(
        defined?(OpenSSL::SSL::TLS1_3_VERSION) ? {
          tls1_3:  OpenSSL::SSL::TLS1_3_VERSION,
          tlsv1_3: OpenSSL::SSL::TLS1_3_VERSION,
        } : {}
      ).freeze
      private_constant :PROTOS_MAP

      PROTO_OP_NO_MAP = {
        OpenSSL::SSL::SSL2_VERSION => OpenSSL::SSL::OP_NO_SSLv2,
        OpenSSL::SSL::SSL3_VERSION => OpenSSL::SSL::OP_NO_SSLv3,
        OpenSSL::SSL::TLS1_VERSION => OpenSSL::SSL::OP_NO_TLSv1,
        OpenSSL::SSL::TLS1_1_VERSION => OpenSSL::SSL::OP_NO_TLSv1_1,
        OpenSSL::SSL::TLS1_2_VERSION => OpenSSL::SSL::OP_NO_TLSv1_2,
      }.merge(
        defined?(OpenSSL::SSL::TLS1_3_VERSION) ? {
          OpenSSL::SSL::TLS1_3_VERSION => OpenSSL::SSL::OP_NO_TLSv1_3,
        } : {}
      ).freeze
      private_constant :PROTO_OP_NO_MAP

      PROTO_OP_NO_SUM = PROTO_OP_NO_MAP.values.reduce {|a, b| a | b }
      private_constant :PROTO_OP_NO_SUM

      # TODO: set_minmax_proto_version => ossl_sslctx_set_minmax_proto_version
      #
      # call-seq:
      #    ctx.set_minmax_proto_version(min, max) -> nil
      #
      # Sets the minimum and maximum supported protocol versions. See #min_version=
      # and #max_version=.
      #
      # = EventMachine
      #
      # This method parses the protocols and sets an internal protocol bitmask
      # for use by EventMachine.set_tls_parms.
      def set_minmax_proto_version(min, max)
        min = self.class.parse_proto_version(min)
        max = self.class.parse_proto_version(max)
        @proto_op_no_bitmask =
          if !(min.nil? && max.nil?)
            range = (min..max)
            PROTO_OP_NO_MAP.reduce(0) {|bitmask, (version, op_no)|
              bitmask | (range.include?(version) ? 0 : op_no)
            }
          else
            0
          end
        self.options &= ~PROTO_OP_NO_SUM     # SSL_CTX_clear_options
        self.options |= @proto_op_no_bitmask # SSL_CTX_set_options
      end

      # @deprecated Only provided for backwards compatibility. Use #min_version=
      # and #max_version= instead.
      def em_set_ssl_versions(*versions)
        @proto_op_no_bitmask = versions.reduce(PROTO_OP_NO_SUM) { |bitmask, version|
          ossl_version = self.class.parse_proto_version(version)
          version_mask = PROTO_OP_NO_MAP.fetch(ossl_version) {
            raise RuntimeError, "unrecognized version %p " % version
          }
          bitmask & ~version_mask
        }
        self.options &= ~PROTO_OP_NO_SUM     # SSL_CTX_clear_options
        self.options |= @proto_op_no_bitmask # SSL_CTX_set_options
      end

      # Takes the version name as string or symbol or a OpenSSL::SSL::*_VERSION.
      # Returns a *EventMachine* version bitmap value (doesn't match OpenSSL
      # const values).
      def self.parse_proto_version(proto)
        return if proto.nil?
        return proto if proto.is_a?(Integer)
        sym = (proto.respond_to?(:to_sym) ? proto : proto.to_str).to_sym
        PROTOS_MAP.fetch(sym) {
          raise ArgumentError, "unrecognized version %p" % [proto]
        }
      end

      # TODO: setup                    => ossl_sslctx_setup
      # The functionality stdlib openssl places here is mostly handled in
      # the constructor for SslBox_t.
      def setup
        return if frozen?

        guard_cert_options!

        instance_variables.each do |name|
          ivar = instance_variable_get(name)
          ivar = -ivar.to_str if ivar.respond_to?(:to_str)
        end

        @setup_done = true
        freeze
      end

      def freeze
        setup unless @setup_done
        super
      end

      private def guard_cert_options!
        [private_key_file, cert_chain_file].each do |file|
          next if file.nil? or file.empty?
          unless File.exist? file
            raise FileNotFoundException,
              "Could not find #{file} for #{self.class}.#{__method__}"
          end
        end

        if !private_key_file.nil? && !private_key_file.empty? &&
            !private_key.nil? && !private_key.empty?
          raise BadPrivateKeyParams,
            "Specifying both private_key and private_key_file not allowed"
        end

        if !cert_chain_file.nil? && !cert_chain_file.empty? &&
            !cert.nil? && !cert.empty?
          raise BadCertParams, "Specifying both cert and cert_chain_file not allowed"
        end

        if (!private_key_file.nil? && !private_key_file.empty?) ||
            (!private_key.nil? && !private_key.empty?)
          if (cert_chain_file.nil? || cert_chain_file.empty?) &&
              (cert.nil? || cert.empty?)
            raise BadParams, "You have specified a private key to use, but not the related cert"
          end
        end
      end

      # @return [String] the client certificate to use, complete with header and
      #   footer. If a cert chain is required, you will have to use the
      #   {cert_chain_file} option. If both {cert_chain_file} and {cert} are
      #   used, BadCertParams will be raised.
      #
      # @todo copy add_certificate from stdlib and deprecate this
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

      #######################################################################
      ## @!group EventMachine-specific attributes

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

      # @deprecated Provided for backwards compatibility.  Use {#ecdh_curves=}.
      #
      # @param curves [String] The curve for ECDHE ciphers. See available ciphers
      #   with 'openssl ecparam -list_curves'
      attr_accessor :ecdh_curve

      # @return [String] The local path of a file containing DH parameters for
      #   EDH ciphers in [PEM
      #   format](http://en.wikipedia.org/wiki/Privacy_Enhanced_Mail) See:
      #   'openssl dhparam'
      attr_accessor :dhparam

      # @deprecated Provided for backwards compatibility.  Use {#ciphers=}.
      #
      # @param ciphers [String] Indicates the available SSL cipher values. Default
      #   value is taken from
      #   {OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:ciphers]}.  Check the
      #   format of the OpenSSL cipher string at
      #   http://www.openssl.org/docs/apps/ciphers.html#CIPHER_LIST_FORMAT.
      def cipher_list=(ciphers)
        self.ciphers = ciphers
      end

      # @!attribute [rw] verify_peer
      # @return [Boolean] if {VERIFY_PEER} is set on {#verify_mode}
      #
      # If true, the {#ssl_verify_peer} callback on the {Connection} object is
      # called with each certificate in the certificate chain provided by the
      # peer. See documentation on {#ssl_verify_peer} for how to use this.
      def verify_peer=(bool)
        return if bool.nil?
        if bool
          self.verify_mode |= OpenSSL::SSL::VERIFY_PEER
        else
          self.verify_mode &= ~OpenSSL::SSL::VERIFY_PEER
        end
        bool
      end

      # @!attribute [rw] fail_if_no_peer_cert
      # @return [Boolean] if {VERIFY_FAIL_IF_NO_PEER_CERT} is set on {#verify_mode}
      #
      # Used by servers in conjunction with verify_peer. If set the SSL
      # handshake will be terminated if the peer does not provide a certificate.
      # Ignored by clients.
      def fail_if_no_peer_cert=(bool)
        return if bool.nil?
        if bool
          self.verify_mode |= OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
        else
          self.verify_mode &= ~OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
        end
        bool
      end

      # @returns [Boolean] if {#verify_mode} is {VERIFY_NONE}
      def verify_none?
        verify_mode == VERIFY_NONE
      end

      # @return [Boolean] if {#verify_mode} includes {VERIFY_PEER}
      def verify_peer?
        (verify_mode & VERIFY_PEER) != 0
      end
      alias verify_peer verify_peer?

      # @return [Boolean] if {#verify_mode} includes {VERIFY_FAIL_IF_NO_PEER_CERT}
      def fail_if_no_peer_cert?
        (verify_mode & VERIFY_FAIL_IF_NO_PEER_CERT) != 0
      end
      alias fail_if_no_peer_cert fail_if_no_peer_cert?

    end

  end
end
