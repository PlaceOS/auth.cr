require "../helper"

module PlaceOS::Auth
  # JWKS parity for the Doorkeeper-openid_connect mount (PPT-2536).
  # Golden values below were computed independently (openssl + python)
  # from the DEV keypair in `authly_adapter.cr`, which the spec
  # environment uses because JWT_SECRET is unset.
  describe Discovery, tags: "jwks" do
    dev_modulus_b64url = "t01C9NBQrA6Y7wyIZtsyur191SwSL3MjR58RIjZ5SEbSyzMG3r9v12qka4UtpB2FmON2vwn0fl_7i3Jgh1Xth_s-TqgYXMebdd123wodrbex5pi3Q7PbQFT6hhNpnsjBh9SubTf-IeTIFeXUyqtqcDBmEoT5GxU6O-Wuch2GtbfEAmaDroy-uyB7P5DxpKLEx8nlVYgpx5g2mx2LufHvykVnx4bFzLezU93SIEW6yjPwUmv9R-wDM_AOg60dIf3hCh1DO-h22aKT8D8ysuFodpLTKCToI_AbK4IYOOgyGHZ7xizXHYXZdsqX5_zBFXu_NOVrSd_QBYYuCxbqe6tz4w"

    it "serves the signing key as a JWKS document with an RFC 7638 kid" do
      result = client.get("/auth/oauth/discovery/keys", headers: HTTP::Headers{"Host" => "localhost"})
      result.status_code.should eq 200

      keys = JSON.parse(result.body)["keys"].as_a
      keys.size.should eq 1
      key = keys.first

      key["kty"].as_s.should eq "RSA"
      key["use"].as_s.should eq "sig"
      key["alg"].as_s.should eq "RS256"
      key["e"].as_s.should eq "AQAB"
      key["n"].as_s.should eq dev_modulus_b64url
      key["kid"].as_s.should eq "WdKmO7zj_nB-doJYcsI6qIVWytuIsw9XfkzDieIwaIY"
    end

    it "publishes a modulus consistent with a 2048-bit key" do
      result = client.get("/auth/oauth/discovery/keys", headers: HTTP::Headers{"Host" => "localhost"})
      n = JSON.parse(result.body)["keys"].as_a.first["n"].as_s
      # 2048-bit modulus = 256 bytes = 342 unpadded base64url chars, no
      # DER sign-padding byte leaking through.
      n.size.should eq 342
      n.should_not start_with "A" # a leading zero byte would encode as "A..."
    end
  end
end
