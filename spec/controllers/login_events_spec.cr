require "webmock"
require "../helper"

# Verifies that successful logins publish a `{user_id, provider}` event
# through `LoginEvents`. We don't go through real Redis here — we swap
# `LoginEvents.publisher` for a recording Proc. This keeps the spec
# independent of the Redis stub in `docker-compose.yml` and proves the
# wire-up (which is the part that can rot under refactors); the actual
# `redis` PUBLISH call is a single line covered by the shard's own
# spec suite.
module PlaceOS::Auth
  describe LoginEvents do
    # Save/restore the publisher on every example so a failure half-way
    # through doesn't leak a recording stub into the next test.
    original_publisher = LoginEvents.publisher
    ::Spec.before_each { LoginEvents.publisher = original_publisher }
    ::Spec.after_each { LoginEvents.publisher = original_publisher }

    describe "publish" do
      it "fires `{user_id, internal}` after a successful POST /auth/signin" do
        calls = [] of Tuple(String, String)
        LoginEvents.publisher = ->(uid : String, provider : String) {
          calls << {uid, provider}
          nil
        }

        authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
        password = "ok-password-1234"
        user = ::PlaceOS::Model::Generator.user(authority)
        user.password = password
        user.save!

        body = {email: user.email.to_s, password: password}.to_json
        headers = HTTP::Headers{
          "Host"         => "localhost",
          "Content-Type" => "application/json",
        }
        result = client.post("/auth/signin", headers: headers, body: body)
        result.status_code.should eq 202

        calls.size.should eq 1
        calls.first[0].should eq user.id
        calls.first[1].should eq "internal"
      ensure
        user.try &.destroy
      end

      it "fires `{user_id, oauth2}` after a successful OAuth callback" do
        calls = [] of Tuple(String, String)
        LoginEvents.publisher = ->(uid : String, provider : String) {
          calls << {uid, provider}
          nil
        }

        authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
        strat = ::PlaceOS::Model::OAuthAuthentication.new
        strat.name = "login-event-#{Random.rand(99999)}"
        strat.client_id = "test"
        strat.client_secret = "test"
        strat.site = "https://idp.example.test"
        strat.authorize_url = "/authorize"
        strat.token_url = "/token"
        strat.auth_scheme = "request_body"
        strat.token_method = "post"
        strat.scope = "openid email"
        strat.raw_info_url = "https://idp.example.test/userinfo"
        strat.info_mappings = {"uid" => "id", "email" => "email", "name" => "name"}
        strat.authority_id = authority.id
        strat.save!

        WebMock.reset
        WebMock.allow_net_connect = false
        WebMock.stub(:post, "https://idp.example.test/token").to_return(
          status: 200,
          headers: HTTP::Headers{"Content-Type" => "application/json"},
          body: {access_token: "x", token_type: "Bearer", expires_in: 3600}.to_json,
        )
        WebMock.stub(:get, "https://idp.example.test/userinfo").to_return(
          status: 200,
          headers: HTTP::Headers{"Content-Type" => "application/json"},
          body: {id: "uid-#{Random.rand(99999)}", email: "bob-#{Random.rand(99999)}@localhost", name: "Bob"}.to_json,
        )

        kickoff = client.get(
          "/auth/oauth2?id=#{URI.encode_www_form(strat.id.as(String))}",
          headers: HTTP::Headers{"Host" => "localhost"},
        )
        kickoff.status_code.should eq 303
        cookie = kickoff.headers["Set-Cookie"].split(';', 2).first.strip
        state = URI::Params.parse(kickoff.headers["Location"].split('?', 2).last)["state"]

        callback = client.get(
          "/auth/oauth2/callback?id=#{URI.encode_www_form(strat.id.as(String))}&code=test-code&state=#{state}",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie},
        )
        callback.status_code.should eq 303

        calls.size.should eq 1
        calls.first[1].should eq "oauth2"
      ensure
        strat.try &.destroy
        WebMock.reset
      end
    end
  end
end
