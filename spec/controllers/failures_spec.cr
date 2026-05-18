require "../helper"

module PlaceOS::Auth
  describe Failures do
    describe "GET /auth/failure" do
      it "returns 401 with an HTML body" do
        result = client.get("/auth/failure", headers: HTTP::Headers{"Host" => "localhost"})
        result.status_code.should eq 401
        result.headers["Content-Type"]?.should match(/text\/html/)
        result.body.should contain "Authentication failed"
      end
    end
  end
end
