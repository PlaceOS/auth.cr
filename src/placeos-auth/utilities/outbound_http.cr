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
  end
end
