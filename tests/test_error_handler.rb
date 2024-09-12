require_relative 'em_test_helper'

class TestErrorHandler < Test::Unit::TestCase
  def setup
    @exception = Class.new(StandardError)
  end

  def test_error_handler
    pend('FIXME: this test is broken in pure ruby mode') if pure_ruby_mode?
    error = nil

    EM.error_handler{ |e|
      error = e
      EM.error_handler(nil)
      EM.stop
    }

    assert_nothing_raised do
      EM.run{
        EM.add_timer(0){
          raise @exception, 'test'
        }
      }
    end

    assert_equal error.class, @exception
    assert_equal error.message, 'test'
  end

  def test_without_error_handler
    assert_raise @exception do
      EM.run{
        EM.add_timer(0){
          raise @exception, 'test'
        }
      }
    end
  end
end
