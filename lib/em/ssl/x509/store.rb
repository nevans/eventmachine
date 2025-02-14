# frozen_string_literal: true

module EventMachine

  module SSL

    module X509

      # A placeholder class for future X509 certificate store functionality
      #
      # From OpenSSL's `X509_STORE_ADD_CERT(3SSL)` man page:
      # The X509_STORE structure is intended to be a consolidated mechanism for
      # holding information about X.509 certificates and CRLs, and constructing
      # and validating chains of certificates terminating in trusted roots.
      class Store

        # This represents the default EventMachine {X509_STORE}, which is not
        # identical to the X509_STORE used by the "openssl" gem, although they
        # should be configured identically.
        DEFAULT = new.freeze

        def self.new
          raise NotImplementedError, "EventMachine::SSL X509_STORE wrapper"
        end
      end

    end
  end
end
