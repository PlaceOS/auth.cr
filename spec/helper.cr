require "action-controller/spec_helper"
require "http"
require "mutex"
require "pg-orm"
require "random"
require "spec"

require "./spec_helpers/*"

include PlaceOS::Auth::SpecClient

# Expose `controller.base_route` for every action-controller subclass so
# specs can build URLs without hardcoding paths.
abstract class ActionController::Base
  macro inherited
    macro finished
      {% begin %}
      def self.base_route
        NAMESPACE[0]
      end
      {% end %}
    end
  end
end

module PlaceOS::Auth
  include Spec::Authentication
end

Spec.before_suite do
  Log.builder.bind("*", backend: PlaceOS::LogBackend::STDOUT, level: :error)
  clear_tables
  PlaceOS::Auth::Spec::Authentication.authenticated
end

Spec.after_suite { clear_tables }

# Application config — pulls in controllers and middleware
require "../src/config"

# Generators for placeos-models
require "placeos-models/spec/generator"

# Configure DB
PgORM::Database.configure { |_| }

# Tables relevant to the auth service. No Elasticsearch — auth flows are
# direct DB lookups, so we don't need refresh_elastic / index awareness.
def clear_tables
  [
    PlaceOS::Model::ApiKey,
    PlaceOS::Model::UserAuthLookup,
    PlaceOS::Model::DoorkeeperApplication,
    PlaceOS::Model::OAuthAuthentication,
    PlaceOS::Model::SamlAuthentication,
    PlaceOS::Model::User,
    PlaceOS::Model::Authority,
  ].each(&.clear)
end

def random_name
  UUID.random.to_s.split('-').first
end
