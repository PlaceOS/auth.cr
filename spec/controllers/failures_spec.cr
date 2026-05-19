require "../helper"

module PlaceOS::Auth
  describe Failures do
    describe "GET /auth/failure" do
      it "returns 200 (matches legacy Ruby) with an HTML body" do
        result = client.get("/auth/failure", headers: HTTP::Headers{"Host" => "localhost"})
        result.status_code.should eq 200
        result.headers["Content-Type"]?.should match(/text\/html/)
        result.body.should contain "Authentication failed"
      end
    end
  end
end
