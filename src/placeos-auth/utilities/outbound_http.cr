require "connect-proxy"
require "http/client"
require "uri"

module PlaceOS::Auth::Utils
  # HTTP clients for requests that leave the cluster for the internet.
  #
  # Crystal's `HTTP::Client` ignores `HTTPS_PROXY` / `HTTP_PROXY`; this routes
  # through the proxy when one is set in the environment (via `connect-proxy`,
  # which reads `https_proxy`, `http_proxy`, `HTTPS_PROXY`, `HTTP_PROXY` and
  # `PROXY_USERNAME` / `PROXY_PASSWORD`).
  #
  # The proxy tunnel is opened only after the timeouts are set, so they cover
  # the connection to the proxy as well.
  module OutboundHTTP
    def self.client(uri : URI, connect_timeout : Time::Span, read_timeout : Time::Span) : HTTP::Client
      client = ConnectProxy::HTTPClient.new(uri, ignore_env: true)
      client.connect_timeout = connect_timeout
      client.read_timeout = read_timeout
      if ConnectProxy.behind_proxy?
        client.set_proxy ConnectProxy.new(*ConnectProxy.parse_proxy_url)
      end
      client
    end

    # Client metadata URLs are supplied by users. Use their vetted addresses for
    # both CONNECT and direct fallback, and keep the hostname for TLS and HTTP.
    def self.client(uri : URI, connect_timeout : Time::Span, read_timeout : Time::Span, addresses : Array(Socket::IPAddress)) : HTTP::Client
      socket = open_tunnel(addresses.first, connect_timeout, read_timeout) if ConnectProxy.behind_proxy?
      socket ||= connect(addresses, connect_timeout)
      socket.read_timeout = read_timeout

      host = uri.host.not_nil!
      tls = OpenSSL::SSL::Socket::Client.new(socket, sync_close: true, hostname: host.rchop('.'))
      port = uri.port || 443
      HTTP::Client.new(tls, host: port == 443 ? host : "#{host}:#{port}")
    rescue error
      socket.try &.close
      raise error
    end

    private def self.open_tunnel(address : Socket::IPAddress, connect_timeout : Time::Span, read_timeout : Time::Span) : TCPSocket?
      proxy = ConnectProxy.new(*ConnectProxy.parse_proxy_url)
      host = address.family.inet6? ? "[#{address.address}]" : address.address
      proxy.open(host, address.port, tls: nil, connect_timeout: connect_timeout, read_timeout: read_timeout).as(TCPSocket)
    rescue IO::Error
      nil
    end

    private def self.connect(addresses : Array(Socket::IPAddress), timeout : Time::Span) : TCPSocket
      last_error = nil
      addresses.each do |address|
        return TCPSocket.new(address.address, address.port, connect_timeout: timeout)
      rescue error : IO::Error
        last_error = error
      end
      raise(last_error || IO::Error.new("No addresses to connect to"))
    end
  end
end
