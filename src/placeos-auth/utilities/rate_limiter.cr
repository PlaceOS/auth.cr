module PlaceOS::Auth
  # A fixed window, in-memory rate limiter. Limits are per process, which is
  # sufficient to blunt abuse of unauthenticated endpoints.
  class Utils::RateLimiter
    MAX_KEYS = 10_000

    getter limit : Int32
    getter window : Time::Span

    @counts = {} of String => Tuple(Int32, Time)
    @lock = Mutex.new

    def initialize(@limit, @window)
    end

    # records an attempt, returning `false` once the limit is exceeded
    def allow?(key : String) : Bool
      now = Time.utc
      @lock.synchronize do
        @counts.reject! { |_key, entry| entry[1] <= now } if @counts.size >= MAX_KEYS
        count, expires = @counts[key]? || {0, now + window}
        count, expires = {0, now + window} if expires <= now
        @counts[key] = {count + 1, expires}
        count < limit
      end
    end

    def clear : Nil
      @lock.synchronize { @counts.clear }
    end
  end
end
