$:.unshift File.dirname(__FILE__)
require 'test_helper'
require 'net/http'

class CloudfilesAuthenticationTest < Test::Unit::TestCase
  
  def setup
    @response = {
      'x-cdn-management-url' => 'http://cdn.example.com/path', 
      'x-storage-url' => 'http://cdn.example.com/storage', 
      'x-auth-token' => 'dummy_token'
    }
    @response.stubs(:code).returns('204')
    @server = mock()
  end
  
  def test_good_authentication
    @server.expects(
      :use_ssl= => true, :verify_mode= => true, 
      :start => true, :finish => true, :get => @response
    )
    Net::HTTP.stubs(:Proxy => mock(:new => @server))

    result = CloudFiles::Authentication.new(@connection, 
      :url => 'https://auth.api.rackspacecloud.com/v1.0',
      :user => 'dummy_user',
      :key => 'dummy_key'
    )

    assert_equal result.class, CloudFiles::Authentication
    assert_equal result.token, 'dummy_token'
    assert_equal @response['x-cdn-management-url'], result.cdn_url
  end                                      
  
  def test_good_authentication_without_cdn
    @response.delete('x-cdn-management-url')
    @server.expects(
      :use_ssl= => true, :verify_mode= => true, 
      :start => true, :finish => true, :get => @response
    )
    Net::HTTP.stubs(:Proxy => mock(:new => @server))

    result = CloudFiles::Authentication.new(@connection, 
      :url => 'https://auth.api.rackspacecloud.com/v1.0',
      :user => 'dummy_user',
      :key => 'dummy_key'
    )

    assert_nil result.cdn_url
  end
  
  def test_snet_authentication
    @server.expects(
      :use_ssl= => true, :verify_mode= => true, 
      :start => true, :finish => true, :get => @response
    )
    Net::HTTP.stubs(:Proxy => mock(:new => @server))

    result = CloudFiles::Authentication.new(@connection, 
      :url => 'https://auth.api.rackspacecloud.com/v1.0',
      :user => 'dummy_user',
      :key => 'dummy_key'
    )

    assert_equal result.class, CloudFiles::Authentication
  end
  
  def test_bad_authentication
    @response.expects(:code => '499')
    @server.expects(
      :use_ssl= => true, :verify_mode= => true, 
      :start => true, :finish => true, :get => @response
    )
    Net::HTTP.stubs(:Proxy => mock(:new => @server))

    assert_raises(CloudFiles::Exception::Authentication) do
      result = CloudFiles::Authentication.new(@connection, 
        :url => 'https://auth.api.rackspacecloud.com/v1.0',
        :user => 'bad_user',
        :key => 'bad_key'
      )
    end
  end
    
  def test_bad_hostname
    Net::HTTP.stubs(:new).raises(CloudFiles::Exception::Connection)

    assert_raises(CloudFiles::Exception::Connection) do
      CloudFiles::Authentication.new(@connection, 
        :url => 'https://auth.api.rackspacecloud.com/v1.0',
        :user => 'dummy_user',
        :key => 'dummy_key'
      )
    end
  end
  
  def test_finishes_request_on_error
    @server.expects(
      :use_ssl= => true, :verify_mode= => true, 
      :start => true, :finish => true
    )
    @server.expects(:get).raises(CloudFiles::Exception::IOException)
    Net::HTTP.stubs(:Proxy => mock(:new => @server))

    assert_raises(CloudFiles::Exception::IOException) do
      CloudFiles::Authentication.new(@connection, 
        :url => 'https://auth.api.rackspacecloud.com/v1.0',
        :user => 'dummy_user',
        :key => 'dummy_key'
      )
    end
  end
    
end
