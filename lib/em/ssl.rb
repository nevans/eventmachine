# frozen_string_literal: true

require "openssl"

require_relative "ssl/x509/store"
require_relative "ssl/x509/store_context"
require_relative "ssl/ssl_context"
require_relative "ssl/ssl_connection"

module EventMachine
  module SSL

    def verify_certificate_identity(cert_pem, hostname)
      x509_cert = OpenSSL::X509::Certificate.new(cert_pem)
      OpenSSL::SSL.verify_certificate_identity(x509_cert, hostname)
    end
    module_function :verify_certificate_identity

  end
end
