# frozen_string_literal: true

require_relative 'em_test_helper'

class TestSSLVerify < Test::Unit::TestCase

  require_relative 'em_ssl_handlers'
  include EMSSLHandlers

  CERT_FROM_FILE = File.read "#{__dir__}/client.crt"

  CERT_CONFIG = { private_key_file: "#{__dir__}/client.key",
                  cert_chain_file:  "#{__dir__}/client.crt" }

  ENCODED_CERT_CONFIG = { private_key_file: "#{__dir__}/encoded_client.key",
                          private_key_pass: 'nicercat',
                          cert_chain_file:  "#{__dir__}/client.crt" }

  def test_fail_no_peer_cert
    omit_if(rbx?)

    server = { verify_peer: true, fail_if_no_peer_cert: true,
      ssl_verify_result: "|RAISE|Verify peer should not get called for a client without a certificate" }

    client_server Client, Server, server: server

    assert_empty Server.preverify_ok # no client cert sent
    assert_empty Client.preverify_ok # no server cert sent

    refute Client.handshake_completed? unless "TLSv1.3" == Client.cipher_protocol
    refute Server.handshake_completed?
  end

  def test_accept_server
    omit_if(EM.library_type == :pure_ruby) # Server has a default cert chain
    omit_if(rbx?)

    server = { verify_peer: true, ssl_verify_result: true }

    client_server Client, Server, client: CERT_CONFIG, server: server

    # OpenSSL can't verify because its x509_store isn't configured
    # but after we insist the chain certs are okay, it's happy with the peer.
    assert_equal Server.preverify_ok, [false, false, true]
    assert_empty Client.preverify_ok # no server cert sent

    assert_equal CERT_FROM_FILE, Server.cert
    assert Client.handshake_completed?
    assert Server.handshake_completed?
  end

  def test_accept_client
    omit_if(EM.library_type == :pure_ruby) # Server has a default cert chain
    omit_if(rbx?)

    client = { verify_peer: true, ssl_verify_result: true }

    client_server Client, Server, server: CERT_CONFIG, client: client

    # OpenSSL can't verify because its x509_store isn't configured
    # but after we insist the chain certs are okay, it's happy with the peer.
    assert_equal Client.preverify_ok, [false, false, true]
    assert_empty Server.preverify_ok # no client cert sent

    assert_equal CERT_FROM_FILE, Client.cert
    assert Client.handshake_completed?
    assert Server.handshake_completed?
  end

  def test_encoded_accept_server
    omit_if(EM.library_type == :pure_ruby) # Server has a default cert chain
    omit_if(rbx?)

    server = { verify_peer: true, ssl_verify_result: true }

    client_server Client, Server, client: ENCODED_CERT_CONFIG, server: server

    # OpenSSL can't verify because its X509_STORE isn't configured
    # but after we insist the chain certs are okay, it's happy with the peer.
    assert_equal Server.preverify_ok, [false, false, true]
    assert_empty Client.preverify_ok # no server cert sent

    assert Client.handshake_completed?
    assert Server.handshake_completed?
    assert_equal CERT_FROM_FILE, Server.cert
  end

  def test_encoded_accept_client
    omit_if(EM.library_type == :pure_ruby) # Server has a default cert chain
    omit_if(rbx?)

    client = { verify_peer: true, ssl_verify_result: true }

    client_server Client, Server, server: ENCODED_CERT_CONFIG, client: client

    # OpenSSL can't verify because its X509_STORE isn't configured
    # but after we insist the chain certs are okay, it's happy with the peer.
    assert_equal Client.preverify_ok, [false, false, true]
    assert_empty Server.preverify_ok # no client cert sent

    assert Client.handshake_completed?
    assert Server.handshake_completed?
    assert_equal CERT_FROM_FILE, Client.cert
  end

  def test_deny_server
    omit_if(EM.library_type == :pure_ruby) # Server has a default cert chain
    omit_if(rbx?)

    server = { verify_peer: true, ssl_verify_result: false }

    client_server Client, Server, client: CERT_CONFIG, server: server

    # OpenSSL can't verify because its X509_STORE isn't configured
    # but it gives up after the first because we agreed with it.
    assert_equal Server.preverify_ok, [false]
    assert_empty Client.preverify_ok # no server cert sent

    assert_equal CERT_FROM_FILE, Server.cert
    refute Client.handshake_completed? unless "TLSv1.3" == Client.cipher_protocol
    refute Server.handshake_completed?
  end

  def test_deny_client
    omit_if(EM.library_type == :pure_ruby) # Server has a default cert chain
    omit_if(rbx?)

    client = { verify_peer: true, ssl_verify_result: false }

    client_server Client, Server, server: CERT_CONFIG, client: client

    # OpenSSL can't verify because its X509_STORE isn't configured
    # but it gives up after the first because we agreed with it.
    assert_equal Client.preverify_ok, [false]
    assert_empty Server.preverify_ok # no client cert sent

    refute Client.handshake_completed? unless "TLSv1.3" == Client.cipher_protocol
    refute Server.handshake_completed?
    assert_equal CERT_FROM_FILE, Client.cert
  end

  def test_backwards_compatible_server
    omit_if(EM.library_type == :pure_ruby) # server has a default cert chain
    omit_if(rbx?)

    server = { verify_peer: true, ssl_verify_result: true,
               ssl_old_verify_peer: true }

    client_server Client, Server, client: CERT_CONFIG, server: server

    # Old server handlers can continue in blissful ignorance of OpenSSL's
    # diagnosis, just as they always have....
    assert_equal Server.preverify_ok, [:a_complete_mystery] * 3

    assert_equal CERT_FROM_FILE, Server.cert
    assert Client.handshake_completed?
    assert Server.handshake_completed?
  end

  def test_backwards_compatible_client
    omit_if(EM.library_type == :pure_ruby) # server has a default cert chain
    omit_if(rbx?)

    client = { verify_peer: true, ssl_verify_result: true,
               ssl_old_verify_peer: true }

    client_server Client, Server, server: CERT_CONFIG, client: client

    # Old client handlers can continue in blissful ignorance of OpenSSL's
    # diagnosis, just as they always have....
    assert_equal Client.preverify_ok, [:a_complete_mystery] * 3
    assert_empty Server.preverify_ok # no client cert sent

    assert_equal CERT_FROM_FILE, Client.cert
    assert Client.handshake_completed?
    assert Server.handshake_completed?
  end

end if EM.ssl?
