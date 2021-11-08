require 'rake/testtask'
require 'rake/clean'
require "openssl"
require "yaml"

Rake::TestTask.new(:test) do |t|
  t.pattern = 'tests/**/test_*.rb'
  t.warning = true
end

directory "tests/fixtures"

namespace "test" do

  namespace "fixtures" do

    CLEAN_FIXTURES = ::Rake::FileList[
      "tests/fixtures/*.csr"
    ]
    CLOBBER_FIXTURES = ::Rake::FileList[
      "tests/fixtures/*.aes-key",
      "tests/fixtures/*.ca-crt",
      "tests/fixtures/*.crt",
      "tests/fixtures/*.key",
      "tests/fixtures/*.pass",
      "tests/fixtures/*.pem",
      "tests/fixtures/*.pub",
    ]

    desc "Remove temporary test fixture files"
    task :clean do
      Rake::Cleaner.cleanup_files(CLEAN_FIXTURES)
    end

    desc "Remove all generated test fixture files"
    task clobber: %i[clean] do
      Rake::Cleaner.cleanup_files(CLOBBER_FIXTURES)
    end

    def write_pem(obj, file, passphrase: nil)
      cipher = OpenSSL::Cipher.new 'AES-128-CBC'
      open(file, "w") do |io|
        io << (
          passphrase ? obj.to_pem(cipher, passphrase) : obj.to_pem
        )
      end
    end

    def x509_subject(cfg)
      subject = cfg.fetch("subject")
      subject.respond_to?(:to_a) ?
        OpenSSL::X509::Name.new(subject.to_a) :
        OpenSSL::X509::Name.parse(subject.to_str)
    end

    def x509_not_after(cfg)
      Time.now + (cfg.fetch("ttl_hours", 24) * 60 * 60)
    end

    def x509_make_csr(cfg, key)
      csr = OpenSSL::X509::Request.new
      csr.subject = x509_subject(cfg)
      csr.version = cfg.fetch("version", 2) # 2 == v3
      csr.public_key = key.public_key
      csr.sign key, OpenSSL::Digest::SHA256.new
      csr
    end

    def x509_random_serial
      rand(1..(2**159-1))
    end

    def get_ca_crt_and_key(ca)
      ca_crtfile = "tests/fixtures/#{ca}.ca-crt"
      ca_keyfile = "tests/fixtures/#{ca}.key"
      Rake::Task[ca_crtfile].invoke
      Rake::Task[ca_keyfile].invoke
      ca_crt = open(ca_crtfile) {|io| OpenSSL::X509::Certificate.new(io.read) }
      ca_key = open(ca_keyfile) {|io| OpenSSL::PKey.read(io) }
      [ca_crt, ca_key]
    end

    # Following the example from the stdlib openssl gem
    def x509_make_ca_crt(cfg, key)
      crt = OpenSSL::X509::Certificate.new
      crt.version    = cfg.fetch("version", 3)
      crt.serial     = x509_random_serial
      crt.not_before = Time.now
      crt.not_after  = x509_not_after(cfg)
      crt.public_key = key.public_key
      crt.subject    = x509_subject(cfg)
      crt.issuer     = crt.subject # CA cert is self-signed!

      xf = OpenSSL::X509::ExtensionFactory.new
      xf.subject_certificate = crt
      xf.issuer_certificate = crt
      crt.add_extension xf.create_extension("subjectKeyIdentifier", "hash")
      crt.add_extension xf.create_extension("basicConstraints", "CA:TRUE", true)
      crt.add_extension xf.create_extension("keyUsage", "cRLSign,keyCertSign", true)

      crt.sign key, OpenSSL::Digest::SHA256.new
      crt
    end

    def x509_issue_crt_from_csr(cfg, csr)
      ca_crt, ca_key = get_ca_crt_and_key(cfg.fetch("ca"))

      crt = OpenSSL::X509::Certificate.new
      crt.version    = cfg.fetch("version", 3)
      crt.serial     = x509_random_serial
      crt.not_before = Time.now
      crt.not_after  = x509_not_after(cfg)
      crt.public_key = csr.public_key
      crt.subject    = csr.subject
      crt.issuer     = ca_crt.subject

      xf = OpenSSL::X509::ExtensionFactory.new
      xf.subject_certificate = crt
      xf.issuer_certificate = ca_crt
      crt.add_extension xf.create_extension("subjectKeyIdentifier", "hash")
      crt.add_extension xf.create_extension("basicConstraints", "CA:FALSE")
      crt.add_extension xf.create_extension(
        "keyUsage", "keyEncipherment,dataEncipherment,digitalSignature"
      )

      crt.sign ca_key, OpenSSL::Digest::SHA256.new
      crt
    end

    rule %r{fixtures/.*\.crt$} => [".csr", ".csr.yml"] do |t|
      csr = OpenSSL::X509::Request.new(File.read(t.source))
      cfg = YAML.load(File.read(t.source.ext(".csr.yml")))
      crt = x509_issue_crt_from_csr(cfg, csr)
      write_pem(crt, t.name)
    end

    rule %r{fixtures/.*\.ca-crt$} => [".key", ".ca.yml"] do |t|
      key = open(t.source) {|io| OpenSSL::PKey.read(io) }
      cfg = YAML.load(File.read(t.source.ext(".ca.yml")))
      crt = x509_make_ca_crt(cfg, key)
      write_pem(crt, t.name)
    end

    rule %r{fixtures/.*\.csr$} => [".key", ".csr.yml"] do |t|
      key = open(t.source) {|io| OpenSSL::PKey.read(io) }
      cfg = YAML.load(File.read(t.source.ext(".csr.yml")))
      csr = x509_make_csr(cfg, key)
      write_pem(csr, t.name)
    end

    rule %r{fixtures/.*\.pub$} => ".key" do |t|
      key = open(t.source) {|io| OpenSSL::PKey.read(io) }
      write_pem(key.public_key, t.name)
    end

    rule %r{fixtures/.*\.key$} => ".aes-key" do |t|
      passphrase = File.read(t.source.ext(".pass"))
      key = open(t.source) {|io| OpenSSL::PKey.read(io, passphrase) }
      write_pem(key, t.name)
    end

    rule %r{fixtures/.*\.aes-key$} => ".pass" do |t|
      cipher = OpenSSL::Cipher.new 'AES-128-CBC'
      passphrase = File.read(t.source)
      key = OpenSSL::PKey::RSA.new 2048
      write_pem(key, t.name, passphrase: passphrase)
    end

    rule %r{fixtures/.*\.pass$} do |t|
      OpenSSL::Random.write_random_file t.name
    end

    rule "tests/fixtures/*" => "tests/fixtures"

  end

end

task clean:   "test:fixtures:clean"
task clobber: "test:fixtures:clobber"
