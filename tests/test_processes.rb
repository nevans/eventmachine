require_relative 'em_test_helper'

class TestProcesses < Test::Unit::TestCase

  if !windows? && !jruby?

    # EM::DeferrableChildProcess is a sugaring of a common use-case
    # involving EM::popen.
    # Call the #open method on EM::DeferrableChildProcess, passing
    # a command-string. #open immediately returns an EM::Deferrable
    # object. It also schedules the forking of a child process, which
    # will execute the command passed to #open.
    # When the forked child terminates, the Deferrable will be signalled
    # and execute its callbacks, passing the data that the child process
    # wrote to stdout.
    #
    def test_deferrable_child_process
      pend('FIXME: this test is broken in pure ruby mode') if pure_ruby_mode?
      ls = ""
      EM.run {
        d = EM::DeferrableChildProcess.open( "ls -ltr" )
        d.callback {|data_from_child|
          ls = data_from_child
          EM.stop
        }
      }
      assert( ls.length > 0)
    end

    def setup
      $out = nil
      $status = nil
    end

    def test_em_system
      pend('FIXME: this test is broken in pure ruby mode') if pure_ruby_mode?
      out, status = nil, nil

      EM.run{
        EM.system('ls'){ |_out,_status| out, status = _out, _status; EM.stop }
      }

      assert(out.length > 0 )
      assert_kind_of(Process::Status, status)
      assert_equal(0, status.exitstatus)
    end

    def test_em_system_bad_exitstatus
      pend('FIXME: this test is broken in pure ruby mode') if pure_ruby_mode?
      status = nil
      sys_pid = nil

      EM.run{
        sys_pid = EM.system('exit 1'){ |_out,_status| status = _status; EM.stop }
      }

      assert_kind_of(Process::Status, status)
      refute_equal(0, status.exitstatus)
      assert_equal sys_pid, status.pid
    end

    def test_em_system_pid
      pend('FIXME: this test is broken in pure ruby mode') if pure_ruby_mode?
      status = nil
      sys_pid = nil

      EM.run{
        sys_pid = EM.system('echo hi', proc{ |_out,_status| status = _status; EM.stop })
      }

      refute_equal(0, sys_pid)
      assert_kind_of(Process::Status, status)
      refute_equal(0, status.pid)
      assert_equal sys_pid, status.pid
    end

    def test_em_system_with_proc
      pend('FIXME: this test is broken in pure ruby mode') if pure_ruby_mode?
      EM.run{
        EM.system('ls', proc{ |out,status| $out, $status = out, status; EM.stop })
      }

      assert( $out.length > 0 )
      assert_kind_of(Process::Status, $status)
      assert_equal(0, $status.exitstatus)
    end

    def test_em_system_with_two_procs
      pend('FIXME: this test is broken in pure ruby mode') if pure_ruby_mode?
      EM.run{
        EM.system('sh', proc{ |process|
          process.send_data("echo hello\n")
          process.send_data("exit\n")
        }, proc{ |out,status|
          $out = out
          $status = status
          EM.stop
        })
      }

      assert_equal("hello\n", $out)
    end

    def test_em_system_cmd_arguments
      pend('FIXME: this test is broken in pure ruby mode') if pure_ruby_mode?
      EM.run{
        EM.system('echo', '1', '2', 'version', proc{ |process|
        }, proc{ |out,status|
          $out = out
          $status = status
          EM.stop
        })
      }

      assert_match(/1 2 version/i, $out)
    end

    def test_em_system_spaced_arguments
      pend('FIXME: this test is broken in pure ruby mode') if pure_ruby_mode?
      EM.run{
        EM.system('ruby', '-e', 'puts "hello"', proc{ |out,status|
          $out = out
          EM.stop
        })
      }

      assert_equal("hello\n", $out)
    end

    def test_em_popen_pause_resume
      pend('FIXME: this test is broken in pure ruby mode') if pure_ruby_mode?
      c_rx = 0

      test_client = Module.new do
        define_method :receive_data do |data|
          c_rx += 1
          pause
          EM.add_timer(0.5) { EM.stop }
        end
      end

      EM.run do
        EM.popen('echo 1', test_client)
      end

      assert_equal 1, c_rx
    end
  else
    warn "EM.popen not implemented, skipping tests in #{__FILE__}"

    # Because some rubies will complain if a TestCase class has no tests
    def test_em_popen_unsupported
      assert true
    end
  end
end
