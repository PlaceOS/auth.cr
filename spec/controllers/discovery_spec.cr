require "../helper"

module PlaceOS::Auth
  # Discovery-surface parity with the legacy Doorkeeper mounts (PPT-2536).
  # Rails served the provider document at four paths (two spec locations
  # at the domain root + two `/auth/.well-known/*` variants from the
  # `scope :auth` mount) and WebFinger at two. All must return identical
  # documents advertising the `/auth/oauth/*` endpoint family.
  describe Discovery, tags: "discovery" do
    get_json = ->(path : String) {
      result = client.get(path, headers: HTTP::Headers{"Host" => "localhost"})
      result.status_code.should eq 200
      JSON.parse(result.body)
    }

    provider_paths = [
      "/.well-known/openid-configuration",
      "/.well-known/oauth-authorization-server",
      "/auth/.well-known/openid-configuration",
      "/auth/.well-known/oauth-authorization-server",
    ]

    it "serves the provider document at all four legacy paths, identically" do
      docs = provider_paths.map { |path| get_json.call(path) }
      docs.each(&.should(eq docs.first))
    end

    it "advertises the legacy Doorkeeper endpoint mounts" do
      doc = get_json.call("/.well-known/openid-configuration")
      doc["authorization_endpoint"].as_s.should end_with "/auth/oauth/authorize"
      doc["token_endpoint"].as_s.should end_with "/auth/oauth/token"
      doc["userinfo_endpoint"].as_s.should end_with "/auth/oauth/userinfo"
      doc["revocation_endpoint"].as_s.should end_with "/auth/oauth/revoke"
      doc["jwks_uri"].as_s.should end_with "/auth/oauth/discovery/keys"
      doc["introspection_endpoint"].as_s.should end_with "/auth/oauth/introspect"
      doc["issuer"].as_s.should start_with "http"
    end

    it "serves WebFinger at both legacy paths" do
      ["/.well-known/webfinger", "/auth/.well-known/webfinger"].each do |path|
        result = client.get(
          "#{path}?resource=acct%3Asupport%40place.tech",
          headers: HTTP::Headers{"Host" => "localhost"},
        )
        result.status_code.should eq 200
        body = JSON.parse(result.body)
        body["subject"].as_s.should eq "acct:support@place.tech"
        links = body["links"].as_a
        links.size.should eq 1
        links.first["rel"].as_s.should eq "http://openid.net/specs/connect/1.0/issuer"
        issuer = get_json.call("/.well-known/openid-configuration")["issuer"].as_s
        links.first["href"].as_s.should eq issuer
      end
    end

    it "rejects WebFinger requests without a resource (400, matching Rails ParameterMissing)" do
      result = client.get("/.well-known/webfinger", headers: HTTP::Headers{"Host" => "localhost"})
      result.status_code.should eq 400
    end

    it "serves POST userinfo at both mounts (OIDC Core §5.3 verb parity)" do
      _, headers = Spec::Authentication.authentication
      headers["Host"] = "localhost"
      ["/auth/userinfo", "/auth/oauth/userinfo"].each do |path|
        result = client.post(path, headers: headers)
        result.status_code.should eq 200
        JSON.parse(result.body)["sub"].as_s.should_not be_empty
      end
    end
  end
end
