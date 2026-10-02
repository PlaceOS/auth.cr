require "crypto/subtle"
require "html"
require "openssl/hmac"
require "uri"

module PlaceOS::Auth
  # The OAuth consent screen shown before issuing an authorization code to a
  # client that requires the user's approval (see
  # `AuthlyAdapter::ClientInfo#consent_required?`).
  #
  # The session cookie is `SameSite=None`, so the approval form is protected
  # by a stateless CSRF token: an HMAC over the session (user + issue time)
  # and every parameter of the authorization request, valid for 10 minutes.
  # A cross-site page can neither read nor forge it, and it can't be replayed
  # for a different client, redirect, scope or PKCE challenge.
  module Utils::Consent
    extend self

    TTL = 10.minutes

    # signs the approval of `request` for the session
    def token(user_id : String, session_iat : String, request : Array(String)) : String
      expires = (Time.utc + TTL).to_unix
      "#{expires}.#{sign(expires, user_id, session_iat, request)}"
    end

    def valid?(token : String, user_id : String, session_iat : String, request : Array(String)) : Bool
      expires_at, _, signature = token.partition('.')
      expires = expires_at.to_i64?
      return false unless expires && Time.utc.to_unix <= expires
      Crypto::Subtle.constant_time_compare(signature, sign(expires, user_id, session_iat, request))
    end

    private def sign(expires : Int64, user_id : String, session_iat : String, request : Array(String)) : String
      # length prefixed so values can't be shifted between fields
      data = String.build do |io|
        {expires.to_s, user_id, session_iat}.each { |value| io << value.bytesize << ':' << value }
        request.each { |value| io << value.bytesize << ':' << value }
      end
      OpenSSL::HMAC.hexdigest(:sha256, "auth.cr/consent/#{COOKIE_SESSION_SECRET}", data)
    end

    # the consent page, every value is escaped
    def page(
      client_name : String,
      client_detail : String,
      redirect_detail : String,
      scopes : Array(String),
      account : String,
      tenant : String,
      fields : Hash(String, String),
    ) : String
      hidden = String.build do |io|
        fields.each do |name, value|
          io << %(<input type="hidden" name=") << HTML.escape(name) << %(" value=") << HTML.escape(value) << %(">)
        end
      end
      permissions = scopes.join { |scope| "<li>#{HTML.escape(describe_scope(scope))}</li>" }
      name = HTML.escape(client_name)

      <<-HTML
        <!doctype html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Authorize #{name}</title>
        <style>
        body{font-family:system-ui,sans-serif;background:#f4f5f7;color:#1d2330;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
        main{background:#fff;max-width:28rem;width:100%;margin:1rem;padding:2rem;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08)}
        h1{font-size:1.25rem;margin:0 0 1rem}dt{font-weight:600;margin-top:.75rem}dd{margin:.25rem 0 0;word-break:break-all}
        ul{margin:.25rem 0 0;padding-left:1.25rem}.actions{display:flex;gap:.75rem;margin-top:1.5rem}
        button{flex:1;padding:.7rem;border-radius:8px;font-size:1rem;cursor:pointer;border:1px solid #c5cad3;background:#fff}
        button[value=allow]{background:#2156d9;border-color:#2156d9;color:#fff}
        </style>
        </head>
        <body>
        <main>
        <h1>Allow #{name} to access your account?</h1>
        <dl>
        <dt>Signed in as</dt><dd>#{HTML.escape(account)} on #{HTML.escape(tenant)}</dd>
        <dt>Application</dt><dd>#{name}<br><small>#{HTML.escape(client_detail)}</small></dd>
        <dt>Returns to</dt><dd>#{HTML.escape(redirect_detail)}</dd>
        <dt>It will be able to</dt><dd><ul>#{permissions}</ul></dd>
        </dl>
        <form method="post" action="/auth/authorize">
        #{hidden}
        <div class="actions">
        <button type="submit" name="consent" value="deny">Deny</button>
        <button type="submit" name="consent" value="allow">Allow</button>
        </div>
        </form>
        </main>
        </body>
        </html>
        HTML
    end

    # where the authorization code will be sent, in plain language
    def redirect_detail(redirect_uri : String) : String
      if Utils::RedirectURI.loopback?(redirect_uri)
        port = URI.parse(redirect_uri).port
        port ? "an application on this computer (port #{port})" : "an application on this computer"
      else
        uri = URI.parse(redirect_uri)
        uri.host.presence || "#{uri.scheme}: (an application on this device)"
      end
    rescue URI::Error
      redirect_uri
    end

    private def describe_scope(scope : String) : String
      case scope
      when "public"         then "Access PlaceOS on your behalf"
      when "openid"         then "Confirm your identity"
      when "profile"        then "View your name and profile"
      when "email"          then "View your email address"
      when "offline_access" then "Stay signed in"
      else                       scope
      end
    end
  end
end
