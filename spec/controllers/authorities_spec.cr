require "../helper"

module PlaceOS::Auth
  describe Authorities do
    describe "GET /auth/authority" do
      it "returns authority details when the host matches" do
        # the suite's authentication helper has already seeded "localhost"
        result = client.get("/auth/authority", headers: HTTP::Headers{"Host" => "localhost"})

        result.status_code.should eq 200
        body = JSON.parse(result.body)
        body["domain"].as_s.should eq "localhost"
        body["production"].as_bool.should be_false
        body["session"].as_bool.should be_false
        body["token_valid"].as_bool.should be_false
        body["version"].as_s.should start_with "v"
      end

      it "returns 404 when no authority matches the host" do
        result = client.get("/auth/authority", headers: HTTP::Headers{"Host" => "nope.example"})
        result.status_code.should eq 404
      end

      it "returns 200 with empty body for unknown host when ?health is set" do
        result = client.get("/auth/authority?health=1", headers: HTTP::Headers{"Host" => "nope.example"})
        result.status_code.should eq 200
        result.body.should be_empty
      end

      it "answers ?health with an empty 200 even for a matching host (no DB lookup)" do
        # The liveness short-circuit runs before any authority resolution, so a
        # matching host still gets the empty process-is-up 200 (not the JSON) —
        # proving a Postgres outage can't 500 the probe.
        result = client.get("/auth/authority?health=true", headers: HTTP::Headers{"Host" => "localhost"})
        result.status_code.should eq 200
        result.body.should be_empty
      end

      it "marks token_valid=true when a Bearer JWT is supplied" do
        _, headers = Spec::Authentication.authentication
        headers["Host"] = "localhost"

        result = client.get("/auth/authority", headers: headers)
        result.status_code.should eq 200
        body = JSON.parse(result.body)
        body["token_valid"].as_bool.should be_true
      end

      it "marks token_valid=true when an X-API-Key is supplied" do
        _, headers = Spec::Authentication.x_api_authentication
        headers["Host"] = "localhost"

        result = client.get("/auth/authority", headers: headers)
        result.status_code.should eq 200
        body = JSON.parse(result.body)
        body["token_valid"].as_bool.should be_true
      end

      it "keeps token_valid=false for a malformed Bearer token" do
        headers = HTTP::Headers{
          "Host"          => "localhost",
          "Authorization" => "Bearer not-a-real-jwt",
        }
        result = client.get("/auth/authority", headers: headers)
        result.status_code.should eq 200
        body = JSON.parse(result.body)
        body["token_valid"].as_bool.should be_false
      end
    end
  end
end
