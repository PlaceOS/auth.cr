require "./authentication"

module PlaceOS::Auth::Spec
  # Asserts that GET /base/{nonsense-id} returns 404.
  def self.test_404(base, model_name, headers : HTTP::Headers, clz : Class = String)
    it "404s if #{model_name} isn't present in database" do
      id = (clz < Int) ? Random.rand(9999).to_s : "#{model_name}-#{Random.rand(9999).to_s.ljust(4, '0')}"
      path = File.join(base, id)
      result = client.get(path, headers: headers)
      result.status_code.should eq 404
    end
  end
end
