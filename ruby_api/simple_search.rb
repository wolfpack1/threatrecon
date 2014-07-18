#!/usr/bin/env ruby

require 'rest-client'
require 'json'

@url = "https://api.threatrecon.co:8080/api/v1/search"
api_key = 'your-api-key'
search = 'evil@example.com'
RestClient.proxy = ENV['https_proxy']

def query_threat_recon(indicator,api_key)
	response = RestClient.post @url, {'api_key' => api_key,'indicator' => indicator}
	case response.code
		when 200
			response_json = JSON.parse(response)
		else
			raise "Unknown Error"
	end
end

results = query_threat_recon(search,api_key)
puts JSON.pretty_generate(results)
