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
    
    def initialize(connection)
      parsed_auth_url = URI.parse(connection.auth_url)
      path = parsed_auth_url.path
      hdrhash = { "X-Auth-User" => connection.authuser, "X-Auth-Key" => connection.authkey }
      begin
        server = get_server(connection, parsed_auth_url)

        if parsed_auth_url.scheme == "https"
          server.use_ssl     = true
          server.verify_mode = OpenSSL::SSL::VERIFY_NONE
        end
        server.start
      rescue
        raise CloudFiles::Exception::Connection, "Unable to connect to #{server}"
      end
      response = server.get(path, hdrhash)
      if (response.code =~ /^20./)
        @token = response["x-auth-token"]
        @storage_url = response["x-storage-url"]
        @cdn_url = response["x-cdn-management-url"] if response["x-cdn-management-url"]
      else
        raise CloudFiles::Exception::Authentication, "Authentication failed"
      end
      server.finish
    end

    private

      def get_server(connection, parsed_auth_url)
        Net::HTTP::Proxy(connection.proxy_host, connection.proxy_port).new(parsed_auth_url.host, parsed_auth_url.port)
      end
  end
end
