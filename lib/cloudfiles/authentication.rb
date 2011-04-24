module CloudFiles
  class Authentication
    # See COPYING for license information.
    # Copyright (c) 2011, Rackspace US, Inc.

    # Performs an authentication to the Cloud Files servers.  Opens a new HTTP connection to the API server,
    # sends the credentials, and looks for a successful authentication.  If it succeeds, it sets the cdmmgmthost,
    # cdmmgmtpath, storagehost, storagepath, authtoken, and authok variables on the connection.  If it fails, it raises
    # an CloudFiles::Exception::Authentication exception.
    #
    # Should probably never be called directly.
    
    attr_reader :token, :cdn_url, :storage_url
    
    def initialize(connection, opts = {})
      parsed_auth_url = URI.parse(opts[:url])
      path = parsed_auth_url.path
      hdrhash = { "X-Auth-User" => opts[:user], "X-Auth-Key" => opts[:key] }
      begin
        server = get_server(parsed_auth_url, opts)
        server.start
      rescue
        raise CloudFiles::Exception::Connection, "Unable to connect to #{server}"
      end

      begin
        response = server.get(path, hdrhash)
        if (response.code =~ /^20./)
          @token = response["x-auth-token"]
          @storage_url = response["x-storage-url"]
          @cdn_url = response["x-cdn-management-url"] if response["x-cdn-management-url"]
        else
          raise CloudFiles::Exception::Authentication, "Authentication failed"
        end
      ensure
        server.finish
      end
    end

    private

    def get_server(parsed_auth_url, opts)
      server = Net::HTTP::Proxy(opts[:proxy_host], opts[:proxy_port]).new(parsed_auth_url.host, parsed_auth_url.port)
      if parsed_auth_url.scheme == "https"
        server.use_ssl     = true
        server.verify_mode = OpenSSL::SSL::VERIFY_NONE
      end
      server
    end
  end
end
