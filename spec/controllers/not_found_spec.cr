require "../helper"

module PlaceOS::Auth
  # Parity for the legacy service's root catch-all (`/*any ->
  # errors#not_found`, PPT-2536): any unmatched path, on any verb,
  # answers 404. The framework's default no-route behaviour already does
  # this; this locks it in.
  describe "catch-all 404", tags: "not-found" do
    headers = HTTP::Headers{"Host" => "localhost"}

    it "returns 404 for an unknown path under /auth" do
      client.get("/auth/does-not-exist-zzz", headers: headers).status_code.should eq 404
    end

    it "returns 404 for an unknown top-level path" do
      client.get("/totally-unknown-zzz", headers: headers).status_code.should eq 404
    end

    it "returns 404 for unmatched verbs too" do
      client.post("/auth/does-not-exist-zzz", headers: headers).status_code.should eq 404
      client.put("/auth/does-not-exist-zzz", headers: headers).status_code.should eq 404
      client.delete("/auth/does-not-exist-zzz", headers: headers).status_code.should eq 404
    end
  end
end
