require "action-controller"
require "placeos-models"
require "uuid"

require "../error"
require "../utilities/*"

module PlaceOS::Auth
  abstract class Application < ActionController::Base
    macro inherited
      Log = ::PlaceOS::Auth::Log.for(self)
    end

    # The legacy Ruby service accepts browser login forms posted as
    # `application/x-www-form-urlencoded`; action-controller only ships a
    # JSON body parser out of the box. Register a form parser so typed
    # body arguments can be built from form posts. Body structs opt in by
    # defining `self.from_form(URI::Params)`.
    add_parser("application/x-www-form-urlencoded") do |klass, body_io, request|
      request_charset = ActionController::Support.charset(request.headers)
      body_io.set_encoding(request_charset) if request_charset
      klass.from_form(URI::Params.parse(body_io.gets_to_end))
    end

    include Utils::CurrentUser
    include Utils::SessionHelper

    # Generic JSON error payload. Same shape as rest-api so clients
    # don't need to branch on which service responded.
    struct CommonError
      include JSON::Serializable

      getter error : String?
      getter backtrace : Array(String)?

      def initialize(error, backtrace = true)
        @error = error.message
        @backtrace = backtrace ? error.backtrace : nil
      end
    end

    # ----- Request id propagation -----

    getter request_id : String { UUID.random.to_s }

    @[AC::Route::Filter(:before_action)]
    def set_request_id
      if (header = request.headers["X-Request-ID"]?) && @request_id.nil?
        @request_id = header
      end

      Log.context.set(
        client_ip: client_ip,
        request_id: request_id,
      )

      response.headers["X-Request-ID"] = request_id
    end

    # ----- Error handlers -----

    @[AC::Route::Exception(Error::Unauthorized, status_code: HTTP::Status::UNAUTHORIZED)]
    def resource_requires_authentication(error) : CommonError
      Log.debug { error.message }
      CommonError.new(error, false)
    end

    @[AC::Route::Exception(Error::Forbidden, status_code: HTTP::Status::FORBIDDEN)]
    def resource_access_forbidden(error) : CommonError
      Log.debug { error.message }
      CommonError.new(error, false)
    end

    @[AC::Route::Exception(Error::NotFound, status_code: HTTP::Status::NOT_FOUND)]
    @[AC::Route::Exception(PgORM::Error::RecordNotFound, status_code: HTTP::Status::NOT_FOUND)]
    def resource_not_found(error) : CommonError
      Log.debug(exception: error) { error.message }
      CommonError.new(error, false)
    end

    @[AC::Route::Exception(Error::Conflict, status_code: HTTP::Status::CONFLICT)]
    def resource_conflict(error) : CommonError
      Log.debug { error.message }
      CommonError.new(error, false)
    end

    @[AC::Route::Exception(Error::BadRequest, status_code: HTTP::Status::BAD_REQUEST)]
    @[AC::Route::Exception(JSON::ParseException, status_code: HTTP::Status::BAD_REQUEST)]
    @[AC::Route::Exception(JSON::SerializableError, status_code: HTTP::Status::BAD_REQUEST)]
    @[AC::Route::Exception(PgORM::Error::RecordInvalid, status_code: HTTP::Status::UNPROCESSABLE_ENTITY)]
    def bad_request(error) : CommonError
      Log.debug(exception: error) { error.message }
      CommonError.new(error, !Auth.production?)
    end

    struct ValidationError
      include JSON::Serializable
      include YAML::Serializable

      getter error : String
      getter failures : Array(NamedTuple(field: Symbol, reason: String))

      def initialize(@error, @failures)
      end
    end

    @[AC::Route::Exception(Error::ModelValidation, status_code: HTTP::Status::UNPROCESSABLE_ENTITY)]
    def model_validation(error) : ValidationError
      ValidationError.new error.message.not_nil!, error.failures
    end

    struct ContentError
      include JSON::Serializable
      include YAML::Serializable

      getter error : String
      getter accepts : Array(String)? = nil

      def initialize(@error, @accepts = nil)
      end
    end

    @[AC::Route::Exception(AC::Route::NotAcceptable, status_code: HTTP::Status::NOT_ACCEPTABLE)]
    @[AC::Route::Exception(AC::Route::UnsupportedMediaType, status_code: HTTP::Status::UNSUPPORTED_MEDIA_TYPE)]
    def bad_media_type(error) : ContentError
      ContentError.new error: error.message.not_nil!, accepts: error.accepts
    end

    struct ParameterError
      include JSON::Serializable
      include YAML::Serializable

      getter error : String
      getter parameter : String? = nil
      getter restriction : String? = nil

      def initialize(@error, @parameter = nil, @restriction = nil)
      end
    end

    @[AC::Route::Exception(AC::Route::Param::MissingError, status_code: HTTP::Status::UNPROCESSABLE_ENTITY)]
    @[AC::Route::Exception(AC::Route::Param::ValueError, status_code: HTTP::Status::BAD_REQUEST)]
    def invalid_param(error) : ParameterError
      ParameterError.new error: error.message.not_nil!, parameter: error.parameter, restriction: error.restriction
    end
  end
end
