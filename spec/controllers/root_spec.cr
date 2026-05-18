require "../helper"

module PlaceOS::Auth
  describe Root do
    describe "GET /auth/healthz" do
      it "returns ok + app metadata" do
        result = client.get("/auth/healthz")
        result.status_code.should eq 200
        body = JSON.parse(result.body)
        body["status"].as_s.should eq "ok"
        body["app"].as_s.should eq APP_NAME
        body["version"].as_s.should eq VERSION
      end
    end
  end
end
