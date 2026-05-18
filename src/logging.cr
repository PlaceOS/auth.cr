require "placeos-log-backend"
require "./constants"

module PlaceOS::Auth::Logging
  ::Log.progname = APP_NAME

  log_backend = PlaceOS::LogBackend.log_backend
  log_level = Auth.production? ? ::Log::Severity::Info : ::Log::Severity::Debug
  namespaces = ["action-controller.*", "place_os.*", "placeos.*"]

  builder = ::Log.builder
  builder.bind("*", log_level, log_backend)
  namespaces.each do |namespace|
    builder.bind(namespace, log_level, log_backend)
  end

  ::Log.setup_from_env(
    default_level: log_level,
    builder: builder,
    backend: log_backend
  )

  PlaceOS::LogBackend.register_severity_switch_signals(
    production: Auth.production?,
    namespaces: namespaces,
    backend: log_backend,
  )
end
