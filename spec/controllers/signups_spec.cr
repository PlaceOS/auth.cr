require "../helper"

module PlaceOS::Auth
  # POST /auth/signup exists for route parity but always answers 403 —
  # auth.cr never issues the social cookie the legacy signup required
  # (OAuth users are auto-created in the callback). This locks in that
  # the route is served and does not regress to 404/405/200 (PPT-2536).
  describe Signups, tags: "signups" do
    it "responds 403 to a signup attempt" do
      result = client.post("/auth/signup", headers: HTTP::Headers{"Host" => "localhost"})
      result.status_code.should eq 403
    end
  end
end
