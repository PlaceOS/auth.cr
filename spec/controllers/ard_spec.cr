require "../helper"

module PlaceOS::Auth
  # The Agentic Resource Discovery manifest, served for the host as nginx routes
  # `/.well-known/*` to auth. It lists the MCP servers by their Server Cards.
  describe Discovery, tags: "discovery" do
    tenant = HTTP::Headers{"Host" => "placeos.acme.com", "X-Forwarded-Proto" => "https"}

    it "lists the MCP servers on this host by their Server Cards" do
      response = client.get("/.well-known/ard.json", headers: tenant)
      response.status_code.should eq 200
      response.headers["Content-Type"].should start_with "application/json"
      response.headers["Access-Control-Allow-Origin"].should eq "*"
      response.headers["Cache-Control"].should eq "public, max-age=3600"

      entries = JSON.parse(response.body)["entries"].as_a
      entries.map(&.["identifier"].as_s).should eq ["urn:air:placeos.acme.com:placeos:workplace", "urn:air:placeos.acme.com:placeos:engine"]
      entries.map(&.["url"].as_s).should eq [
        "https://placeos.acme.com/api/staff/v1/mcp/server-card",
        "https://placeos.acme.com/api/engine/v2/mcp/server-card",
      ]
      entries.each do |entry|
        entry["type"].should eq "application/mcp-server-card+json"
        entry["displayName"].as_s.should_not be_empty
        # Server Card descriptions are limited to 100 characters
        entry["description"].as_s.size.should be <= 100
        entry["capabilities"].as_a.should_not be_empty
        # ARD warns outside 2 to 5 representative queries
        (2..5).should contain entry["representativeQueries"].as_a.size
        entry["data"]?.should be_nil
      end
    end

    it "publishes each tenant under its own host" do
      entries = JSON.parse(client.get("/.well-known/ard.json", headers: HTTP::Headers{"Host" => "localhost:8080"}).body)["entries"].as_a
      entries.first["identifier"].should eq "urn:air:localhost:placeos:workplace"
      entries.first["url"].as_s.should end_with "://localhost/api/staff/v1/mcp/server-card"
    end

    it "serves the same document as the AI Catalog" do
      catalog = client.get("/.well-known/ai-catalog.json", headers: tenant)
      catalog.status_code.should eq 200
      catalog.headers["Content-Type"].should start_with "application/ai-catalog+json"
      catalog.headers["Access-Control-Allow-Origin"].should eq "*"
      document = JSON.parse(catalog.body)
      document["specVersion"].should eq "1.0"
      document.should eq JSON.parse(client.get("/.well-known/ard.json", headers: tenant).body)
    end
  end
end
