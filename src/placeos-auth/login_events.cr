require "json"
require "redis"

module PlaceOS::Auth
  # Publishes successful logins onto a Redis pub/sub channel so the
  # rest of the PlaceOS stack can observe authentication events
  # (cache invalidation, audit logs, etc.).
  #
  # Mirrors the legacy Ruby service's `placeos/auth/login` channel —
  # downstream subscribers expect the exact same payload shape:
  # `{"user_id": "...", "provider": "..."}`.
  module LoginEvents
    Log = ::PlaceOS::Auth::Log.for(self)

    # Indirection so tests can swap in a recording double without
    # spinning up a Redis subscriber. Production code calls
    # `LoginEvents.publish` which delegates here; tests reassign
    # `LoginEvents.publisher` to a Proc that captures invocations.
    class_property publisher : Proc(String, String, Nil) = ->(user_id : String, provider : String) {
      publish_to_redis(user_id, provider)
    }

    # Single shared connection. `redis` is thread-safe per docs but we
    # only `publish` (no blocking subscribers) so a single instance is
    # fine. Lazy-init so tests don't pay the connection cost unless
    # something actually publishes.
    @@redis : ::Redis? = nil
    @@redis_mutex = Mutex.new

    # Fire-and-forget. Errors are logged at `warn` and swallowed —
    # a flaky Redis must never block a successful login.
    def self.publish(user : ::PlaceOS::Model::User, provider : String) : Nil
      uid = user.id
      return if uid.nil?
      publisher.call(uid, provider)
    end

    # :nodoc:
    def self.publish_to_redis(user_id : String, provider : String) : Nil
      redis_url = REDIS_URL
      return if redis_url.nil? || redis_url.empty?

      payload = {user_id: user_id, provider: provider}.to_json
      redis = ensure_connection(redis_url)
      return if redis.nil?
      redis.publish(LOGIN_EVENTS_CHANNEL, payload)
    rescue ex
      Log.warn(exception: ex) { {action: "login_events.publish", message: "ignoring failure"} }
    end

    # Resets the singleton — useful for tests that want a clean state
    # or to recover after a Redis-side restart.
    def self.reset_connection : Nil
      @@redis_mutex.synchronize do
        @@redis.try &.close
        @@redis = nil
      end
    end

    private def self.ensure_connection(url : String) : ::Redis?
      @@redis_mutex.synchronize do
        existing = @@redis
        return existing if existing
        @@redis = ::Redis.new(url: url)
      end
    end
  end
end
