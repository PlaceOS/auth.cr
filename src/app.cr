require "option_parser"
require "http/client"

# Server defaults
port = 3000
host = "127.0.0.1"
cluster = false
process_count = 1

# Command line options
OptionParser.parse(ARGV.dup) do |parser|
  parser.banner = "Usage: #{PlaceOS::Auth::APP_NAME} [arguments]"

  parser.on("-b HOST", "--bind=HOST", "Specifies the server host") { |h| host = h }
  parser.on("-p PORT", "--port=PORT", "Specifies the server port") { |p| port = p.to_i }

  parser.on("-w COUNT", "--workers=COUNT", "Specifies the number of processes to handle requests") do |w|
    cluster = true
    process_count = w.to_i
  end

  parser.on("-r", "--routes", "List the application routes") do
    ActionController::Server.print_routes
    exit 0
  end

  parser.on("-e", "--env", "List the application environment") do
    ENV.accessed.sort.each &->puts(String)
    exit 0
  end

  parser.on("-v", "--version", "Display the application version") do
    puts "#{PlaceOS::Auth::APP_NAME} v#{PlaceOS::Auth::VERSION}"
    exit 0
  end

  parser.on("-c URL", "--curl=URL", "Perform a basic health check by requesting the URL") do |url|
    begin
      response = HTTP::Client.get url
      exit 0 if (200..499).includes? response.status_code
      puts "health check failed, received response code #{response.status_code}"
      exit 1
    rescue error
      error.inspect_with_backtrace(STDOUT)
      exit 2
    end
  end

  parser.on("-d", "--docs", "Outputs OpenAPI documentation for this service") do
    puts ActionController::OpenAPI.generate_open_api_docs(
      title: PlaceOS::Auth::APP_NAME,
      version: PlaceOS::Auth::API_VERSION,
      description: "PlaceOS Auth service (Crystal)"
    ).to_yaml
    exit 0
  end

  parser.on("-h", "--help", "Show this help") do
    puts parser
    exit 0
  end

  fail = ->(error : String, option : String) {
    STDERR.puts "#{error}: #{option}"
    puts parser
    exit 1
  }

  parser.missing_option { |o| fail.call("Error: Missing Option", o) }
  parser.invalid_option { |o| fail.call("Error: Invalid Option", o) }
end

# Requiring config here ensures that the option parser runs before
# we attempt to connect to redis etc.
require "./config"

# Configure the database connection. First check if PG_DATABASE_URL environment variable
# is set. If not, assume database configuration are set via individual environment variables
if pg_url = ENV["PG_DATABASE_URL"]?
  PgORM::Database.parse(pg_url)
else
  PgORM::Database.configure { |_| }
end

# NOTE: `PlaceOS::Auth::AuthlyAdapter.configure!` already ran when the
# `authly_adapter` source file was required (at compile/load time). No
# duplicate call needed here.

PlaceOS::Auth::Log.info {
  "launching #{PlaceOS::Auth::APP_NAME} v#{PlaceOS::Auth::VERSION} " \
  "(#{PlaceOS::Auth::BUILD_COMMIT} @ #{PlaceOS::Auth::BUILD_TIME.strip})"
}

server = ActionController::Server.new(port, host)

# Start clustering
server.cluster(process_count, "-w", "--workers") if cluster

terminate = Proc(Signal, Nil).new do |signal|
  puts " > terminating gracefully"
  spawn { server.close }
  signal.ignore
end

Signal::INT.trap &terminate
Signal::TERM.trap &terminate

server.run do
  PlaceOS::Auth::Log.info { "listening on #{server.print_addresses}" }
  STDOUT.flush
end

PlaceOS::Auth::Log.info { "#{PlaceOS::Auth::APP_NAME} signs off" }
