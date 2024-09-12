require_relative 'em_test_helper'
require 'tempfile'

class TestFileWatch < Test::Unit::TestCase
  if windows?
    def test_watch_file_raises_unsupported_error
      pend("\nFIXME: Windows as of 2018-06-23 on 32 bit >= 2.4 (#{RUBY_VERSION} #{RUBY_PLATFORM})") if RUBY_PLATFORM[/i386-mingw/] && RUBY_VERSION >= '2.4'
      assert_raises(EM::Unsupported) do
        EM.run do
          file = Tempfile.new("fake_file")
          EM.watch_file(file.path)
        end
      end
    end
  elsif EM.respond_to? :watch_filename
    module FileWatcher
      def file_modified
        $modified = true
      end
      def file_deleted
        $deleted = true
      end
      def unbind
        $unbind = true
        EM.stop
      end
    end

    def setup
      EM.kqueue = true if EM.kqueue?
    end

    def teardown
      EM.kqueue = false if EM.kqueue?
    end

    def test_events
      pend('FIXME: EM.watch_filename is broken in pure ruby mode') if pure_ruby_mode?
      omit_if(solaris?)
      EM.run{
        file = Tempfile.new('em-watch')
        $tmp_path = file.path

        # watch it
        watch = EM.watch_file(file.path, FileWatcher)
        $path = watch.path

        # modify it
        File.open(file.path, 'w'){ |f| f.puts 'hi' }

        # delete it
        EM.add_timer(0.01){ file.close; file.delete }
      }

      assert_equal($path, $tmp_path)
      assert($modified)
      assert($deleted)
      assert($unbind)
    end

    # Refer: https://github.com/eventmachine/eventmachine/issues/512
    def test_invalid_signature
      pend('FIXME: EM.watch_filename is broken in pure ruby mode') if pure_ruby_mode?
      # This works fine with kqueue, only fails with linux inotify.
      omit_if(EM.kqueue?)

      EM.run {
        file = Tempfile.new('foo')

        w1 = EventMachine.watch_file(file.path)
        w2 = EventMachine.watch_file(file.path)

        assert_raise EventMachine::InvalidSignature do
          w2.stop_watching
        end
        w1.stop_watching rescue nil
        EM.stop
      }
    end
  else
    warn "EM.watch_file not implemented, skipping tests in #{__FILE__}"

    # Because some rubies will complain if a TestCase class has no tests
    def test_em_watch_file_unsupported
      assert true
    end
  end
end
