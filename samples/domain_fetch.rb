#!/usr/bin/env ruby
require 'yaml'
def usage
	puts "-a action -c datafile"
	puts "action=format,resolve, route_add, route_del"
	puts "datafile action rely on files"
	exit
end
def format
	domains = []
	File.read("domain.txt").each_line do |line|
		domain_name = line.gsub(/"|"|:|,/, '').split[0]
		domains << domain_name.chop
	end
	fd = File.new("domain.yaml", File::CREAT|File::TRUNC|File::RDWR, 0644)
	domain_yaml = domains.to_yaml
	fd.write(domain_yaml)
	fd.close
end
def resolve
	text = File.read("domains.yaml")
	fmt_yaml = YAML.load(text)
	result = []
	fmt_yaml.each do |dom|
		res = `dig #{dom} @8.8.8.8`
		match_data = /ANSWER SECTION:/.match(res)
		if match_data
			resolve_dic = {}
			resolve_dic[:domian] = dom
			post_txt =  match_data.post_match
			ips = []
			post_txt.each_line do |line_txt|
				unless /;;/ =~ line_txt
					txt_split = line_txt.split
					if txt_split.size == 5 && txt_split[3] == 'A'
						ip = txt_split[4]
						ips << ip
					end
				end
			end
			resolve_dic[:ip] = ips
			result << resolve_dic
		end
		puts resolve_dic
	end
	puts result
	fd = File.new("result.yaml", File::CREAT|File::TRUNC|File::RDWR, 0644)
	result_yaml = result.to_yaml
	fd.write(result_yaml)
	fd.close
end
def get_domain_ip
	domain_fd = File.read("result.yaml")
	domain_yaml = YAML.load(domain_fd)
	ip_net_dic = {}
	ip_dic = {}
	domain_yaml.each do |dom_dic|
		# puts dom_dic
		puts dom_dic[:domian]
		dom_dic[:ip].each do |ip|
			net=`ipcalc #{ip}/24|grep Network|awk '{print $2}'`.chomp
			ip_net_dic[net] ||= []
			ip_net_dic[net] << ip
		end
	end
	ip_net_dic.keys
end

def route_add
	ips = get_domain_ip
	ips.each do |ip|
		`ip route add #{ip} dev tun9`
		puts "add route #{ip} is done"
	end
end

def route_del
	ips = get_domain_ip
	ips.each do |ip|
		`ip route del #{ip} dev tun9`
		puts "del route #{ip} is done"
	end
end

if ARGV.size != 2
	usage
end
if ARGV[0] == "route_add"
	route_add
elsif  ARGV[0] == "route_del"
	route_del
else
	puts "args error"
end
