#!/usr/bin/env ruby

require 'rest-client'
require 'json'

@url = "https://api.threatrecon.co:8080/api/v1/search"
api_key = 'your-api-key'
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

puts "Please Enter an Indicator: "
search = gets.chomp

results = query_threat_recon(search,api_key)

indicator_meta = Array.new
related_indicators = Array.new

if results["Msg"].eql?("Success")
	results["Results"].each do |item|
		if item["RootNode"].empty? and search.eql?(item["Indicator"])
			indicator_meta << {"Reference" => item["Reference"],
					  "Source" => item["Source"],
					  "KillChain" => item["KillChain"],
					  "FirstSeen" => item["FirstSeen"],
					  "LastSeen" => item["LastSeen"],
					  "Attribution" => item["Attribution"],
					  "ProcessType" => item["ProcessType"],
					  "Country" => item["Country"],
					  "Tags" => item["Tags"],
					  "Comments" => item["Comments"],
					  "Confidence" => item["Confidence"]}
		end
		if item["RootNode"].eql?(search)
			related_indicators << {"Indicator" => item["Indicator"],
                                       	       "ProcessType" => item["ProcessType"],
                                               "Rdata" => item["Rdata"],
                                               "Rrname" => item["Rrname"],
                                               "RootNode" => item["RootNode"]}
		end
		if item["RootNode"] != "" and search != item["RootNode"]
                        related_indicators << {"Indicator" => item["Indicator"],
                                               "ProcessType" => item["ProcessType"],
                                               "Rdata" => item["Rdata"],
                                               "Rrname" => item["Rrname"],
                                               "RootNode" => item["RootNode"]}		
		end
	end
end

if indicator_meta.length.eql?(0) and related_indicators.length.eql?(0)
	puts "COMMENT: #{search} is a derived indicator...metadata is inherited from the root node"
end

if indicator_meta.length > 0
	puts "ThreatRecon has found the following metadata on #{search}"
	indicator_meta.first.each_key do |key|
		puts "#{key} : #{indicator_meta.first[key]}"
	end
end

if related_indicators.length > 0
	puts "ThreatRecon has found the following indicator(s) that are related to #{search}"
	related_indicators.each do |elem|
		if elem["Indicator"] != search
			puts
			puts "******************"
			puts "Related indicator: #{elem["Indicator"]}"
			puts "Relationship Type: #{elem["ProcessType"]}"
			puts "Relationship Pivot: #{elem["Rdata"]}" unless elem["Rdata"].empty?
			puts "Rrname: #{elem["Rrname"]}" unless (elem["Rrname"].nil? or elem["Rrname"].empty?) and (elem["Rrname"] != elem["Indicator"])
			puts "******************"
		else
			                        puts
                        puts "******************"
                        puts "Related indicator: #{elem["RootNode"]}"
                        puts "Relationship Type: #{elem["ProcessType"]}"
                        puts "Relationship Pivot: #{elem["Rdata"]}" unless elem["Rdata"].empty?
                        puts "Rrname: #{elem["Rrname"]}" unless (elem["Rrname"].nil? or elem["Rrname"].empty?) and (elem["Rrname"] != elem["RootNode"])
                        puts "******************"

		end
	end
end
