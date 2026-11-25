require "spec"
require "../src/placeos-auth/utilities/outbound_http"

describe PlaceOS::Auth::Utils::OutboundHTTP do
  it "tunnels to the validated address and port for client metadata" do
    previous_proxy = ConnectProxy.proxy_uri
    proxy = TCPServer.new("127.0.0.1", 0)
    ConnectProxy.proxy_uri = "http://127.0.0.1:#{proxy.local_address.port}"
    request = Channel(String?).new(1)

    spawn do
      proxy.accept? do |socket|
        request.send(socket.gets(chomp: true))
        while (line = socket.gets(chomp: true)) && !line.empty?
        end
        socket << "HTTP/1.0 200 Connection Established\r\n\r\n"
      end
    end

    uri = URI.parse("https://metadata.invalid:8443/client.json")
    addresses = [Socket::IPAddress.new("2001:db8::1", 8443)]
    expect_raises(OpenSSL::SSL::Error) do
      PlaceOS::Auth::Utils::OutboundHTTP.client(uri, 1.second, 1.second, addresses)
    end
    request.receive.should eq "CONNECT [2001:db8::1]:8443 HTTP/1.0"
  ensure
    ConnectProxy.proxy_uri = previous_proxy
    proxy.try &.close
  end

  it "uses the same validated address for a direct fallback" do
    previous_proxy = ConnectProxy.proxy_uri
    proxy = TCPServer.new("127.0.0.1", 0)
    origin = TCPServer.new("127.0.0.1", 0)
    ConnectProxy.proxy_uri = "http://127.0.0.1:#{proxy.local_address.port}"

    spawn do
      proxy.accept? do |socket|
        while (line = socket.gets(chomp: true)) && !line.empty?
        end
        socket << "HTTP/1.0 403 Forbidden\r\n\r\n"
      end
    end
    spawn { origin.accept?(&.read_byte) }

    address = origin.local_address
    uri = URI.parse("https://metadata.invalid:#{address.port}/client.json")
    expect_raises(OpenSSL::SSL::Error) do
      PlaceOS::Auth::Utils::OutboundHTTP.client(uri, 1.second, 1.second, [address])
    end
  ensure
    ConnectProxy.proxy_uri = previous_proxy
    proxy.try &.close
    origin.try &.close
  end
end
