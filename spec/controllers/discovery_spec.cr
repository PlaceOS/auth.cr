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

    # ---- OI-07: where the issuer comes from ----------------------------
    #
    # `Discovery#request_issuer` builds the issuer from `X-Forwarded-Proto`
    # and the `Host` header, and `Response#initialize` derives every advertised
    # endpoint from it. That makes the Host header an input to a document that
    # relying parties treat as authoritative, so the invariants worth pinning
    # are: the issuer is exactly an origin, it is the origin the document was
    # fetched from, and no endpoint ever escapes it. (The remaining half of
    # OI-07 — that the token `iss` claim is deliberately *not* this value —
    # is asserted in `oidc_id_token_spec.cr`, where real tokens are minted.)
    describe "issuer derivation (OI-07)" do
      # An origin and nothing more: no path, no trailing slash, no userinfo
      # component, no embedded whitespace or control characters.
      origin_only = /\A https?:\/\/ [A-Za-z0-9.\-]+ (?::\d+)? \z/x

      it "pins the issuer to the Host the document was fetched from" do
        ["localhost", "auth.tenant-b.example"].each do |host|
          provider_paths.each do |path|
            result = client.get(path, headers: HTTP::Headers{"Host" => host})
            result.status_code.should eq 200
            issuer = JSON.parse(result.body)["issuer"].as_s

            issuer.should match origin_only
            uri = URI.parse(issuer)
            uri.host.should eq host
            # An origin and nothing else. A path or query here would mean
            # something request-controlled had been concatenated in, and a
            # userinfo component is the classic way to make an issuer *look*
            # like it belongs to another host.
            uri.path.should eq ""
            uri.query.should be_nil
            uri.user.should be_nil
            uri.fragment.should be_nil
            uri.scheme.as(String).should match /\Ahttps?\z/
          end
        end
      end

      it "confines every advertised endpoint to the issuer origin" do
        ["localhost", "auth.tenant-b.example"].each do |host|
          doc = JSON.parse(client.get(
            "/.well-known/openid-configuration",
            headers: HTTP::Headers{"Host" => host},
          ).body)
          issuer = doc["issuer"].as_s

          %w[
            authorization_endpoint token_endpoint userinfo_endpoint
            revocation_endpoint jwks_uri introspection_endpoint
          ].each do |field|
            doc[field].as_s.should start_with "#{issuer}/"
          end
        end
      end

      it "never leaks another authority's host into a foreign-Host document" do
        # `localhost` is the only seeded authority, so if any part of the
        # document were built from configuration rather than the request the
        # real host would show up here. An RP fetching through a proxy for
        # tenant B must be handed tenant B's URLs and nothing else.
        result = client.get(
          "/.well-known/openid-configuration",
          headers: HTTP::Headers{"Host" => "auth.tenant-b.example"},
        )
        result.status_code.should eq 200
        result.body.should contain "auth.tenant-b.example"
        result.body.should_not contain "localhost"
      end

      it "takes the issuer scheme from X-Forwarded-Proto" do
        # In every real deployment auth.cr sits behind nginx terminating TLS,
        # so without this the document would send relying parties to plain
        # http endpoints and they would refuse to post credentials there.
        result = client.get(
          "/.well-known/openid-configuration",
          headers: HTTP::Headers{"Host" => "localhost", "X-Forwarded-Proto" => "https"},
        )
        result.status_code.should eq 200
        doc = JSON.parse(result.body)
        doc["issuer"].as_s.should eq "https://localhost"
        doc["token_endpoint"].as_s.should eq "https://localhost/auth/oauth/token"
        doc["jwks_uri"].as_s.should eq "https://localhost/auth/oauth/discovery/keys"

        # WebFinger is bootstrapped before discovery, so it has to agree.
        webfinger = client.get(
          "/.well-known/webfinger?resource=acct%3Asupport%40place.tech",
          headers: HTTP::Headers{"Host" => "localhost", "X-Forwarded-Proto" => "https"},
        )
        webfinger.status_code.should eq 200
        JSON.parse(webfinger.body)["links"].as_a.first["href"].as_s.should eq "https://localhost"
      end
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
