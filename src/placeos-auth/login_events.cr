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

    # Single shared connection, lazily created so tests don't pay the
    # connection cost unless something actually publishes.
    #
    # A `::Redis` instance is NOT safe for concurrent use: two fibers (or,
    # with execution contexts, two threads) issuing commands on the same
    # socket read each other's replies, and one of them can be left waiting
    # forever on data the other already buffered — hanging that login
    # request indefinitely. Every command therefore runs under the mutex.
    @@redis : ::Redis? = nil
    @@redis_mutex = Mutex.new

    # Bounds how long a slow or unreachable Redis can hold up a login (and,
    # via the mutex, every login queued behind it).
    REDIS_TIMEOUT = 2.seconds

    # Fire-and-forget. Errors are logged at `warn` and swallowed —
    # a flaky Redis must never block a successful login.
    def self.publish(user : ::PlaceOS::Model::User, provider : String) : Nil
      uid = user.id
      return if uid.nil?
      publisher.call(uid, provider)
    end

    # Records a successful login: bumps `login_count`, stamps
    # `last_login`, persists, and publishes the Redis event. Mirrors
    # the legacy Ruby `Authentication.after_login_block` which did
    # the same two things (counter + Redis) atomically.
    #
    # Persistence failures are logged but not raised — the request
    # has already established a session at this point and we don't
    # want a transient DB blip to bounce the user back to the login
    # page.
    def self.record_login(user : ::PlaceOS::Model::User, provider : String) : Nil
      user.login_count = (user.login_count || 0_i64) + 1
      user.last_login = Time.utc
      user.save
    rescue ex
      Log.warn(exception: ex) { {action: "login_events.record_login", message: "ignored persistence failure"} }
    ensure
      publish(user, provider)
    end

    # :nodoc:
    def self.publish_to_redis(user_id : String, provider : String) : Nil
      redis_url = REDIS_URL
      return if redis_url.nil? || redis_url.empty?

      payload = {user_id: user_id, provider: provider}.to_json
      @@redis_mutex.synchronize do
        redis = @@redis ||= ::Redis.new(
          url: redis_url,
          connect_timeout: REDIS_TIMEOUT,
          command_timeout: REDIS_TIMEOUT,
        )
        begin
          redis.publish(LOGIN_EVENTS_CHANNEL, payload)
        rescue ex
          # drop the connection so the next login starts from a clean socket
          # rather than one that may hold a half-read reply
          redis.close rescue nil
          @@redis = nil
          raise ex
        end
      end
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
  end
end
