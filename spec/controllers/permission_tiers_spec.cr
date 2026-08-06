require "../helper"
require "jwt"

module PlaceOS::Auth
  # Permission tiers — PPT-2536 test-matrix rows AZ-03 and AZ-04.
  #
  # Every authorization decision in PlaceOS is made *downstream* of auth.cr,
  # by `check_admin` / `check_support` in rest-api and staff-api, and all of
  # them read one claim: `u.p`. Bit 0 is support, bit 1 is sys_admin
  # (`ClaimsProvider#permissions_value`). auth.cr's job is to encode that
  # honestly for every tier.
  #
  # Existing specs only ever mint tokens for a support+admin user, so `u.p`
  # was asserted at 3 and nowhere else — a bug that, say, floored the value
  # at 1 or dropped the support bit would have passed the whole suite while
  # silently promoting or demoting every non-admin in the estate.
  describe OAuth, tags: "permissions" do
    # Full authorize → token exchange for a user at a given tier, returning
    # the decoded access-token claims alongside the fixtures to clean up.
    issue_for = ->(support : Bool, sys_admin : Bool, slug : String) {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      password = "bcrypt-please-#{Random.rand(999_999)}"
      user = ::PlaceOS::Model::Generator.user(authority).tap do |u|
        u.support = support
        u.sys_admin = sys_admin
        u.password = password
        u.save!
      end

      # `DoorkeeperApplication#uid` is MD5(redirect_uri), so each app needs
      # its own redirect or the second `save!` collides.
      redirect = "https://tier.example/cb-#{slug}-#{Random.rand(999_999)}"
      app = ::PlaceOS::Model::DoorkeeperApplication.new
      app.name = "tier-#{slug}-#{Random.rand(999_999)}"
      app.redirect_uri = redirect
      app.scopes = "public"
      app.owner_id = user.id.as(String)
      app.confidential = true
      app.save!

      cookie = Spec.signin!(client, user, password)
      authorize_path = String.build do |io|
        io << "/auth/authorize?response_type=code"
        io << "&client_id=" << URI.encode_www_form(app.uid.as(String))
        io << "&redirect_uri=" << URI.encode_www_form(redirect)
        io << "&scope=public"
      end
      authorize_result = client.get(authorize_path, headers: HTTP::Headers{
        "Host" => "localhost", "Cookie" => cookie,
      })
      authorize_result.status_code.should eq 302
      code = URI::Params.parse(authorize_result.headers["Location"].split('?', 2).last)["code"]

      token_result = client.post("/auth/token",
        headers: HTTP::Headers{
          "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
        },
        body: URI::Params.build { |fp|
          fp.add("grant_type", "authorization_code")
          fp.add("client_id", app.uid.as(String))
          fp.add("client_secret", app.secret)
          fp.add("code", code)
          fp.add("redirect_uri", redirect)
        })
      token_result.status_code.should eq 200

      access_token = JSON.parse(token_result.body)["access_token"].as_s
      claims, _ = JWT.decode(access_token, ::Authly.config.public_key.as(String), JWT::Algorithm::RS256)

      {user, app, access_token, claims, cookie}
    }

    # ---- AZ-04: the `u.p` encoding, tier by tier ------------------------

    describe "permission claim by tier (AZ-04)" do
      it "issues u.p=0 for a plain user" do
        user, app, _token, claims, _cookie = issue_for.call(false, false, "plain")
        claims["u"]["p"].as_i.should eq 0
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "issues u.p=1 for a support user who is not an admin" do
        # The tier the matrix flagged as untested. Support is the widest
        # non-admin grant in the product — it opens rest-api's `check_support`
        # surface — so an over- or under-set bit here is a real access change.
        user, app, _token, claims, _cookie = issue_for.call(true, false, "support")
        claims["u"]["p"].as_i.should eq 1
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "issues u.p=2 for an admin who is not support" do
        user, app, _token, claims, _cookie = issue_for.call(false, true, "admin")
        claims["u"]["p"].as_i.should eq 2
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "issues u.p=3 for a user who is both" do
        user, app, _token, claims, _cookie = issue_for.call(true, true, "both")
        claims["u"]["p"].as_i.should eq 3
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # ---- AZ-03: a plain user's token is still a working credential ------

    describe "plain user with the public scope (AZ-03)" do
      it "reads its own identity through userinfo" do
        # `u.p=0` restricts what downstream services will *do* for the
        # caller; it must not make the token itself unusable. The 403-on-
        # admin-endpoints half of this row belongs to rest-api and is
        # covered by `integration/integrate.sh` §8.
        user, app, token, claims, _cookie = issue_for.call(false, false, "read")

        claims["scope"].as_a.map(&.as_s).should eq ["public"]
        claims["u"]["p"].as_i.should eq 0

        result = client.get("/auth/userinfo", headers: HTTP::Headers{
          "Host" => "localhost", "Authorization" => "Bearer #{token}",
        })
        result.status_code.should eq 200
        JSON.parse(result.body)["sub"].as_s.should eq user.id.as(String)
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "is recognised as a valid token by the authority endpoint" do
        user, app, token, _claims, _cookie = issue_for.call(false, false, "authority")

        result = client.get("/auth/authority", headers: HTTP::Headers{
          "Host" => "localhost", "Authorization" => "Bearer #{token}",
        })
        result.status_code.should eq 200
        JSON.parse(result.body)["token_valid"].as_bool.should be_true
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # ---- AZ-04: support does not reach the admin surface ----------------

    describe "admin surface gating (AZ-04)" do
      # `applications_spec.cr` pins the two ends of this gate — an admin
      # session gets 204, a plain session gets 404. The middle tier is the
      # one that matters for the encoding above: `require_admin` tests
      # `user.sys_admin` alone, so support must NOT be enough. If it ever
      # started consulting `user_support?` instead, this is what fails.
      it "hides the collection from a support user who is not an admin" do
        user, app, _token, _claims, cookie = issue_for.call(true, false, "gate")

        result = client.get("/auth/oauth/applications", headers: HTTP::Headers{
          "Host" => "localhost", "Cookie" => cookie,
        })
        result.status_code.should eq 404
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "refuses to create an application for a support user" do
        # The write half of the same gate — `before_action :require_admin`
        # covers every action, and a 404 here (not 422/403) is Doorkeeper's
        # "the resource is invisible" behaviour.
        user, app, _token, _claims, cookie = issue_for.call(true, false, "gate-write")

        result = client.post("/auth/oauth/applications",
          headers: HTTP::Headers{
            "Host" => "localhost", "Cookie" => cookie,
            "Content-Type" => "application/json",
          },
          body: {name: "nope-#{Random.rand(999_999)}", redirect_uri: "https://nope.example/cb"}.to_json)
        result.status_code.should eq 404
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end
  end
end
