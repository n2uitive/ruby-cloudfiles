$:.unshift File.dirname(__FILE__)
require 'test_helper'

class CloudfilesAuthenticationTest < Test::Unit::TestCase
  

  def test_good_authentication
    response = {'x-cdn-management-url' => 'http://cdn.example.com/path', 'x-storage-url' => 'http://cdn.example.com/storage', 'x-auth-token' => 'dummy_token'}
    response.stubs(:code).returns('204')
    server = mock(:use_ssl= => true, :verify_mode= => true, :start => true, :finish => true)
    server.stubs(:get).returns(response)
    CloudFiles::Authentication.any_instance.stubs(:get_server).returns(server)
    @connection = stub(:authuser => 'dummy_user', :authkey => 'dummy_key', :cdnmgmthost= => true, :cdnmgmtpath= => true, :cdnmgmtport= => true, :cdnmgmtscheme= => true, :storagehost= => true, :storagepath= => true, :storageport= => true, :storagescheme= => true, :authtoken= => true, :authok= => true, :snet? => false, :auth_url => 'https://auth.api.rackspacecloud.com/v1.0', :cdn_available? => true, :cdn_available= => true)

    result = CloudFiles::Authentication.new(@connection)

    assert_equal result.class, CloudFiles::Authentication
    assert_equal result.token, 'dummy_token'
    assert_equal response['x-cdn-management-url'], result.cdn_url
  end                                      
  
  def test_good_authentication_without_cdn
    response = {'x-storage-url' => 'http://cdn.example.com/storage', 'x-auth-token' => 'dummy_token'}
    response.stubs(:code).returns('204')
    server = mock(:use_ssl= => true, :verify_mode= => true, :start => true, :finish => true)
    server.stubs(:get).returns(response)
    CloudFiles::Authentication.any_instance.stubs(:get_server).returns(server)
    @connection = stub(:authuser => 'dummy_user', :authkey => 'dummy_key', :cdnmgmthost= => true, :cdnmgmtpath= => true, :cdnmgmtport= => true, :cdnmgmtscheme= => true, :storagehost= => true, :storagepath= => true, :storageport= => true, :storagescheme= => true, :authtoken= => true, :authok= => true, :snet? => false, :auth_url => 'https://auth.api.rackspacecloud.com/v1.0', :cdn_available? => true, :cdn_available= => true)

    result = CloudFiles::Authentication.new(@connection)

    assert_nil result.cdn_url
  end
  
  def test_snet_authentication
    response = {'x-cdn-management-url' => 'http://cdn.example.com/path', 'x-storage-url' => 'http://cdn.example.com/storage', 'authtoken' => 'dummy_token'}
    response.stubs(:code).returns('204')
    server = mock(:use_ssl= => true, :verify_mode= => true, :start => true, :finish => true)
    server.stubs(:get).returns(response)
    CloudFiles::Authentication.any_instance.stubs(:get_server).returns(server)
    @connection = stub(:authuser => 'dummy_user', :authkey => 'dummy_key', :cdnmgmthost= => true, :cdnmgmtpath= => true, :cdnmgmtport= => true, :cdnmgmtscheme= => true, :storagehost= => true, :storagepath= => true, :storageport= => true, :storagescheme= => true, :authtoken= => true, :authok= => true, :snet? => true, :auth_url => 'https://auth.api.rackspacecloud.com/v1.0', :cdn_available? => true, :cdn_available= => true)
    result = CloudFiles::Authentication.new(@connection)
    assert_equal result.class, CloudFiles::Authentication
  end
  
  def test_bad_authentication
    response = mock()
    response.stubs(:code).returns('499')
    server = mock(:use_ssl= => true, :verify_mode= => true, :start => true)
    server.stubs(:get).returns(response)
    CloudFiles::Authentication.any_instance.stubs(:get_server).returns(server)
    @connection = stub(:authuser => 'bad_user', :authkey => 'bad_key', :authok= => true, :authtoken= => true,  :auth_url => 'https://auth.api.rackspacecloud.com/v1.0', :cdn_available? => true)
    assert_raises(CloudFiles::Exception::Authentication) do
      result = CloudFiles::Authentication.new(@connection)
    end
  end
    
  def test_bad_hostname
    Net::HTTP.stubs(:new).raises(CloudFiles::Exception::Connection)
    @connection = stub(:proxy_host => nil, :proxy_port => nil, :authuser => 'bad_user', :authkey => 'bad_key', :authok= => true, :authtoken= => true, :auth_url => 'https://auth.api.rackspacecloud.com/v1.0', :cdn_available? => true)
    assert_raises(CloudFiles::Exception::Connection) do
      result = CloudFiles::Authentication.new(@connection)
    end
  end
    
end
