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

# Boot-time schema check (XO-03).
#
# The auth pod runs NO migrations of its own, so the platform migration
# `20260519100000000_add_oauth_tokens.sql` has to land before this service
# does. When that ordering slips the failure is genuinely nasty and was
# reproduced in `tasks/PPT-2536/cutover/rehearse.sh` step 8: auth.cr boots,
# reports HEALTHY (the probes are deliberately DB-free — CFG-04), stays in the
# load balancer, and answers a perfectly valid refresh token with
# `invalid_grant`. Every login breaks while the symptom points squarely at the
# client's token rather than at a missing table.
#
# So: say it once, loudly, at boot. Deliberately NOT fatal — a transient DB
# problem during startup should not crash-loop the login path, and the check
# cannot always tell "table absent" from "database briefly unreachable". The
# stronger version (gate readiness on this) would keep the pod out of the load
# balancer entirely, but that trades a silent failure for an outage and belongs
# with the CFG-01/CFG-02 deployment work rather than here.
begin
  present = false
  PgORM::Database.connection do |db|
    present = db.scalar("SELECT to_regclass('public.oauth_tokens') IS NOT NULL") == true
  end
  unless present
    PlaceOS::Auth::Log.error {
      "oauth_tokens is MISSING — the platform migration " \
      "20260519100000000_add_oauth_tokens.sql has not been applied. Token " \
      "storage, refresh and revocation will all fail with `invalid_grant` " \
      "even for valid tokens. This is a deployment ordering fault, not a " \
      "client error."
    }
  end
rescue e
  PlaceOS::Auth::Log.warn(exception: e) {
    "could not verify the oauth_tokens schema at boot — if the database is " \
    "reachable and this persists, check that the platform migrations ran"
  }
end

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
