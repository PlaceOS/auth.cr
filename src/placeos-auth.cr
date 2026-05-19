require "action-controller/logger"
require "secrets-env"

require "./constants"
require "./placeos-auth/error"
require "./placeos-auth/authly_adapter"
require "./placeos-auth/oauth_providers"
require "./placeos-auth/controllers/application"
require "./placeos-auth/controllers/*"

module PlaceOS::Auth
end
