# frozen_string_literal: true

require "openssl"

module EventMachine

  module SSL

    # This provides an API that is more like stdlib's OpenSSL::SSL::SSLSocket,
    # while allowing EventMachine::Connection to keep its original API for
    # backwards compatibility.
    class SSLConnection

      def initialize(em_connection, context)
        @signature = em_connection.signature
        @em_connection = em_connection
        context.setup
        @context = context
        @sync_close = true
        @hostname = nil
      end

      # Server hostname for SNI.  This must be set before calling start_tls.
      attr_accessor :hostname

      # The EM::Connection managed by this EM::SSL::SSLConnection.
      attr_reader :em_connection

      # The {SSLContext} object used in this connection.
      attr_reader :context

      # Whether to close the underlying socket as well, when the SSL/TLS
      # connection is shut down. This defaults to +true+ (unlike stdlib).
      #
      # @note In EventMachine, this only controls the behavior during handshake
      #   failure, e.g. if an exception occurs in {start_tls} or
      #   {post_connection_check}.  There is no way to close close the TLS
      #   connection without *also* closing the underlying connection.
      attr_accessor :sync_close

      # Use this instead of connect or accept.  The {em_connection} already
      # knows whether it's a server or client.
      def start_tls
        if em_connection.ssl_connection != self
          raise ArgumentError, "EM::Connection doesn't match EM::SSL::SSLConnection"
        end
        EventMachine::set_tls_parms(@signature, @context, @hostname)
        EventMachine::start_tls @signature
        self
      rescue RuntimeError => ex
        em_connection.close_connection if sync_close
        case ex.message
        when /X509_check_private_key/
          raise InvalidPrivateKey, ex.message
        else
          raise
        end
      rescue Exception
        em_connection.close_connection if sync_close
        raise
      end
      alias connect start_tls
      alias accept  start_tls

      # The OpenSSL::X509::Certificate for this connections’s peer.
      def peer_cert
        OpenSSL::X509::Certificate.new(em_connection.get_peer_cert)
      end

      def ssl_handshake_completed
        post_connection_check(hostname) if context.post_connection_check?
      rescue Exception
        em_connection.close_connection if sync_close
        raise
      end

      # call-seq:
      #   ssl.post_connection_check(hostname) -> true
      #
      # Perform hostname verification following RFC 6125.
      #
      # This method MUST be called after calling #connect to ensure that the
      # hostname of a remote peer has been verified.
      def post_connection_check(hostname)
        if peer_cert.nil?
          msg = "Peer verification enabled, but no certificate received."
          if using_anon_cipher?
            msg += " Anonymous cipher suite #{cipher[0]} was negotiated. " \
              "Anonymous suites must be disabled to use peer verification."
          end
          $stderr.puts "OpenSSL::SSL::SSLError, \"#{msg}\""
          raise OpenSSL::SSL::SSLError, msg
        end

        unless OpenSSL::SSL.verify_certificate_identity(peer_cert, hostname)
          $stderr.puts "OpenSSL::SSL::SSLError, hostname \"#{hostname}\" does not match the server certificate"
          raise OpenSSL::SSL::SSLError, "hostname \"#{hostname}\" does not match the server certificate"
        end
        return true
      end

      def cipher
        name  = EventMachine::get_cipher_name @signature
        proto = EventMachine::get_cipher_protocol @signature
        bits  = EventMachine::get_cipher_bits @signature
        [name, proto, bits, bits]
      end

      private

      def using_anon_cipher?
        ctx = OpenSSL::SSL::SSLContext.new
        ctx.ciphers = "aNULL"
        ctx.ciphers.include?(cipher)
      end

    end

    Connection = SSLConnection
  end
end
