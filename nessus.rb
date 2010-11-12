#! /usr/bin/env ruby

#nessus V2 parser for Dan.

require 'optparse'
require 'uri'
require 'net/https'
require 'rexml/document'
require 'csv'
require 'ruport'

include REXML

options = {}

optparse = OptionParser.new do |opts|
    opts.banner = "Nessus Parser for Dan\nUsage: ./nivil.rb [options] "
    opts.on('-u', '--user USER', 'Username to login to Nessus') do |username|
      options[:username] = username
    end
    opts.on('-p', '--password PASSWD', 'Password to login to Nessus') do |passwd|
      options[:passwd] = passwd
    end
    opts.on('-s', '--server SERVER', 'Server name (localhost is default)') do |server|
      options[:server] = server
    end
    opts.on('-l', '--policy POLICY', 'Policy to scan with' ) do |policy|
      options[:policy] = policy
    end
    opts.on('-t', '--target TARGET', 'Target to scan') do |target|
      options[:target] = target
    end
    opts.on('-n', '--name NAME', 'Scan name') do |name|
      options[:name] = name
    end
    opts.on('-h', '--help', 'Display help') do
      puts opts
      exit
    end
    opts.on('-v', '--verbose', 'Show Scan Progress to STD OUT') do
      options[:verbose] = true
    end
    opts.on('-f', '--file INFILE', 'File of hosts to scan') do |file|
      options[:file] = file
    end
    opts.on('-o', '--output OUTFILE', 'Name of IVIL output file') do |out|
      options[:out] = out
    end
    opts.on('--show-policies', 'Shows Server Policies') do
      options[:showpol] = true
    end
    opts.on('--show-reports', 'Shows Server Reports') do
      options[:showrpt] = true
    end
    opts.on('--get-report RPTID', 'Download Report and Export to IVIL') do |rpt|
        options[:rptid] = rpt
    end
    case ARGV.length
    when 0
      puts opts
      exit
    end
    @fopts = opts
end
optparse.parse!

# Our Connection Class

class NessusConnection
    def initialize(user, pass, server)
        @username = user
        @passwd = pass
        @server = server
        @nurl = "https://#{@server}:8834/"
        @token = nil
    end
    
    def connect(uri, post_data)
        url = URI.parse(@nurl + uri)
        request = Net::HTTP::Post.new( url.path )
        request.set_form_data(post_data)
        if not defined? @https
          @https = Net::HTTP.new( url.host, url.port )
          @https.use_ssl = true
          @https.verify_mode = OpenSSL::SSL::VERIFY_NONE
        end
        begin
          res = @https.request(request)
        rescue
          puts("error connecting to server: #{@nurl} with URI: #{uri}")
          exit
        end
        return res.body
    end
end

class NessusXMLStreamParser
	
    attr_accessor :on_found_host

    def initialize(&block)
      reset_state
      on_found_host = block if block
    end

    def reset_state
      @host = {
        'report_name' => nil,
        'hname' => nil,
        'addr' => nil,
        'host_start' => nil,
        'host_end' => nil,
        'host_fqdn' => nil,
        'netbios_name' => nil,
        'mac' => nil,
        'os' => nil,
        'report_item' => {
          'port' => nil,
          'svc_name'  => nil,
          'proto' => nil,
          'severity' => nil,
          'nasl' => nil,
          'plugin_name' => nil,
          'plugin_family' => nil,
          'solution' => nil,
          'risk_factor' => nil,
          'description' => nil,
          'plugin_publication_date' => nil,
          'plugin_modification_date' => nil,
          'patch_publication_date' => nil,
          'metasploit_name' => nil,
          'exploit_framework_metasploit' => nil,
          'vuln_publication_date' => nil,
          'synopsis' => nil,
          'plugin_output' => nil,
          'plugin_version' => nil,
          'cvss_vector' => nil,
          'cvss_base_score' => nil,
          'cvss_temporal_vector' => nil,
          'cvss_temporal_score' => nil,
          'exploit_available' => nil,
          'exploitability_ease' => nil,
          'see_also' => [],
          'cve' => [],
          'bid' => [],
          'xref' => [],
          'msf' => nil }}
      @state = :generic_state
    end

    def tag_start(name, attributes)
        case name
        when "Report"
          @host['report_name'] = attributes['name']
        when "tag"
          if attributes['name'] == "mac-address"
            @state = :is_mac
          end
          if attributes['name'] == "host-fqdn"
            @state = :is_fqdn
          end
          if attributes['name'] == "ip-addr"
            @state = :is_ip
          end
          if attributes['name'] == "host-ip"
            @state = :is_ip
          end
          if attributes['name'] == "operating-system"
            @state = :is_os
          end
          if attributes['name'] == "HOST_START"
            @state = :host_start
          end
          if attributes['name'] == "HOST_END"
            @state = :host_end
          end
        when "ReportHost"
          @host['hname'] = attributes['name']
        when "ReportItem"
          @cve = Array.new
          @bid = Array.new
          @xref = Array.new
          @see_also = Array.new
          @report_item = Hash.new
          @report_item['nasl'] = attributes['pluginID']
          @report_item['port'] = attributes['port']
          @report_item['proto'] = attributes['protocol']
          @report_item['svc_name'] = attributes['svc_name']
          @report_item['severity'] = attributes['severity']
          @report_item['plugin_name'] = attributes['pluginName']
          @report_item['plugin_family'] = attributes['pluginFamily']
        when "description"
          @state = :is_desc
        when "cve"
          @state = :is_cve
        when "bid"
          @state = :is_bid
        when "xref"
          @state = :is_xref
        when "see_also"
          @state = :see_also
        when "solution"
          @state = :is_solution
        when "metasploit_name"
          @state = :msf
        when "risk_factor"
          @state = :risk_factor
        when "plugin_publication_date"
          @state = :plugin_publication_date
        when "plugin_modification_date"
          @state = :plugin_modification_date
        when "patch_publication_date"
          @state = :patch_publication_date
        when "metasploit_name"
          @state = :metasploit_name
        when "exploit_framework_metasploit"
          @state = :exploit_framework_metasploit
        when "vuln_publication_date"
          @state = :vuln_publication_date
        when "synopsis"
          @state = :synopsis
        when "plugin_output"
          @state = :plugin_output
        when "plugin_version"
          @state = :plugin_version
        when "cvss_vector"
          @state = :cvss_vector
        when "cvss_base_score"
          @state = :cvss_base_score
        when "cvss_temporal_vector"
          @state = :cvss_temporal_vector
        when "cvss_temporal_score"
          @state = :cvss_temporal_score
        when "exploit_available"
          @state = :exploit_available
        when "exploitability_ease"
          @state = :exploitability_ease
        end
        
    end
    
    def text(str)
        case @state
        when :host_start
          @host['host_start'] = str
        when :host_end
          @host['host_end'] = str
        when :is_fqdn
          @host['hname'] = str
        when :is_ip
          @host['addr'] = str
        when :is_os
          @host['os'] = str
        when :is_mac
          @host['mac'] = str
        when :is_desc
          @report_item['description'] = str
        when :is_cve
          @cve.push str
        when :is_bid
          @bid.push str
        when :is_xref
          @xref.push str
        when :see_also
          @see_also.push str
        when :msf
          @report_item['msf'] = str
        when :risk_factor
          @report_item['risk_factor'] = str
        when :plugin_publication_date
          @report_item['plugin_publication_date'] = str
        when :plugin_modification_date
          @report_item['plugin_modification_date'] = str
        when :patch_publication_date
          @report_item['patch_publication_date'] = str
        when :metasploit_name
          @report_item['metasploit_name'] = str
        when :exploit_framework_metasploit
          @report_item['exploit_framework_metasploit'] = str
        when :vuln_publication_date
          @report_item['vuln_publication_date'] = str
        when :synopsis
          @report_item['synopsis'] = str
        when :plugin_output
          @report_item['plugin_output'] = str
        when :plugin_version
          @report_item['plugin_version'] = str
        when :cvss_vector
          @report_item['cvss_vector'] = str
        when :cvss_base_score
          @report_item['cvss_base_score'] = str
        when :cvss_temporal_vector
          @report_item['cvss_temporal_vector'] = str
        when :cvss_temporal_score
          @report_item['cvss_temporal_score'] = str
        when :exploit_available
          @report_item['exploit_available'] = str
        when :exploitability_ease
          @report_item['exploitability_ease'] = str
        end
    end

    def tag_end(name)
        case name
        when "ReportHost"
          on_found_host.call(@host) if on_found_host
          reset_state
        when "ReportItem"
          @report_item['cve'] = @cve
          @report_item['bid'] = @bid
          @report_item['xref'] = @xref
          @report_item['see_also'] = @see_also
          @host['report_item'] = @report_item
        end
        @state = :generic_state
    end

    # We don't need these methods, but they're necessary to keep REXML happy
    #
    def xmldecl(version, encoding, standalone); end
    def cdata; end
    def comment(str); end
    def instruction(name, instruction); end
    def attlist; end
end # end of parser class

#@host = {
#        'report_name' => nil,
#        'hname' => nil,
#        'addr' => nil,
#        'host_start' => nil,
#        'host_end' => nil,
#        'host_fqdn' => nil,
#        'netbios_name' => nil,
#        'mac' => nil,
#        'os' => nil,
#        'report_item' => {
#          'port' => nil,
#          'svc_name'  => nil,
#          'proto' => nil,
#          'severity' => nil,
#          'nasl' => nil,
#          'plugin_name' => nil,
#          'plugin_family' => nil,
#          'solution' => nil,
#          'risk_factor' => nil,
#          'description' => nil,
#          'plugin_publication_date' => nil,
#          'plugin_modification_date' => nil,
#          'patch_publication_date' => nil,
#          'metasploit_name' => nil,
#          'exploit_framework_metasploit' => nil,
#          'vuln_publication_date' => nil,
#          'synopsis' => nil,
#          'plugin_output' => nil,
#          'plugin_version' => nil,
#          'cvss_vector' => nil,
#          'cvss_base_score' => nil,
#          'cvss_temporal_vector' => nil,
#          'cvss_temporal_score' => nil,
#          'exploit_available' => nil,
#          'exploitability_ease' => nil,
#          'see_also' => [],
#          'cve' => [],
#          'bid' => [],
#          'xref' => [],
#          'msf' => nil }}

def parse_nessus(content, options)
    parser = NessusXMLStreamParser.new
    #CSV.open("#{options[:out]}.csv", "w") do |csv|
    #  csv << ["Finding ID", "hostname", "IP Address", "Host Scan Start", "Host Scan End", "Host FQDN", "Netbios Name", "Mac Address", "Operating System",
    #          "Port", "Service Name", "Plugin ID", "Plugin Name", "Plugin Family", "Solution", "Risk Factor", "Description", "Plugin Publication Date",
    #          "Plugin Modification Date", "Patch Publication Date", "Metasploit Name", "Metasploit Exploit Available", "Vuln Publication Date", "Synopsis",
    #          "Plugin Output", "Plugin Version", "CVSS Vector", "CVSS Base Score", "CVSS Temporal Vector", "CVSS Temporal Score", "Exploit Available",
    #          "Exploitability Ease", "See Also", "CVE", "BID", "XREF"]
      parser.on_found_host = Proc.new do |host|
          p host
          #row = Array.new
          report_name = host['report_name']
          hname = host['hname']
          hname.gsub!(/[\n\r]/," or ") if hname
          addr = host['addr'] || host['hname']
          addr.gsub!(/[\n\r]/," or ") if addr
          
          os = host['os']
          os.gsub!(/[\n\r]/," or ") if os
          
          
          
          mac = host['mac']
          mac.gsub!(/[\n\r]/," or ") if mac
          
          host['report_item'].each do |item|
              
              
              
              #item['cve'].i
                
              
              
          #   row = Array.new
          #    #print("#{addr} | #{os} | #{port} | Sev #{severity} \n")
          #    row << ["#{host['addr']}-#{item['port']}-#{item['nasl']}", "#{hname}", "#{addr}", "#{host['host_start']}", "#{host['host_end']}",
          #            "#{host['host_end']}", "#{host['host_end']}", "#{mac}", "#{os}", "#{item['port']}", "#{item['nasl']}", "#{item['plugin_name']}",
          #            "#{item['plugin_family']}", "#{item['solution']}", "#{item['risk_factor']}", "#{item['description']}",
          #            "#{item['plugin_publication_date']}", "#{item['plugin_modification_date']}", "#{item['patch_publication_date']}",
          #            "#{item['metasploit_name']}", "#{item['exploit_framework_metasploit']}", "#{item['vuln_publication_date']}",
          #            "#{item['synopsis']}", "#{item['plugin_output']}", "#{item['plugin_version']}", "#{item['cvss_vector']}",
          #            "#{item['cvss_base_score']}", "#{item['cvss_temporal_vector']}", "#{item['cvss_temporal_score']}",
          #            "#{item['exploit_available']}", "#{item['exploitability_ease']}", "#{item['see_also']}", "#{cve}",
          #            "#{item['bid']}", "#{item['xref']}"]
          #    csv << row
          #    
          #end
          
      end
      REXML::Document.parse_stream(content, parser)
    
    end
end

def show_policy(options)
    uri = "scan/list"
    post_data = { "token" => @token }
    stuff = @n.connect(uri, post_data)
    docxml = REXML::Document.new(stuff)
    policies=Array.new
    docxml.elements.each('/reply/contents/policies/policies/policy') { |policy|
      entry=Hash.new
      entry['id']=policy.elements['policyID'].text
      entry['name']=policy.elements['policyName'].text
      entry['comment']=policy.elements['policyComments'].text
      policies.push(entry)
    }
    puts("ID\tName")
    policies.each do |policy|
      puts("#{policy['id']}\t#{policy['name']}")
    end 
end

def login(options)
    uri = "login"
    post_data =  { "login" => options[:username], "password" => options[:passwd] }
    #p post_data
    stuff = @n.connect(uri, post_data)
    docxml = REXML::Document.new(stuff)
    if docxml == ''
      @token=''
    else
      @token = docxml.root.elements['contents'].elements['token'].text
      @name = docxml.root.elements['contents'].elements['user'].elements['name'].text
      @admin = docxml.root.elements['contents'].elements['user'].elements['admin'].text
    end
end

def show_reports(options)
    uri = "report/list"
    post_data = { "token" => @token }
    stuff = @n.connect(uri, post_data)
    docxml = REXML::Document.new(stuff)
    reports=Array.new
    docxml.elements.each('/reply/contents/reports/report') {|report|
      entry=Hash.new
      entry['id']=report.elements['name'].text if report.elements['name']
      entry['name']=report.elements['readableName'].text if report.elements['readableName']
      entry['status']=report.elements['status'].text if report.elements['status']
      entry['timestamp']=report.elements['timestamp'].text if report.elements['timestamp']
      reports.push(entry)
    }
    puts("ID\tName")
    reports.each do |report|
      puts("#{report['id']}\t#{report['name']}")
    end 
end

def get_report(options)
    file = nil
    uri = "file/report/download"
    post_data = { "token" => @token, "report" => options[:rptid]  }
    stuff = @n.connect(uri, post_data)
    if options[:out]
      File.open("#{options[:out]}.nessus", 'w') {|f| f.write(stuff) }
      puts("#{options[:out]} written.")
      parse_nessus(stuff, options)
      exit
    end
    
end


@n = NessusConnection.new(options[:username], options[:passwd], options[:server])
#ok lets check we have everything.

if options[:showpol]
    login(options)
    show_policy(options)
    exit
end

if options[:showrpt]
    login(options)
    show_reports(options)
    exit
end

if options[:rptid]
    login(options)
    get_report(options)
    exit
end

if !(options[:username] and options[:out] and options[:passwd] and options[:server] and options[:policy] and (options[:target] or options[:file]))
    puts
    puts("**[FAIL]** Missing Arguments")
    puts
    puts @fopts
    exit
end

#login
login(options)

##verify policy
uri = "scan/list"
pid = options[:policy]
post_data = { "token" => @token }
stuff = @n.connect(uri, post_data)
docxml = REXML::Document.new(stuff)
policies=Array.new
docxml.elements.each('/reply/contents/policies/policies/policy') { |policy|
    entry=Hash.new
    entry['id']=policy.elements['policyID'].text
    entry['name']=policy.elements['policyName'].text
    entry['comment']=policy.elements['policyComments'].text
    policies.push(entry)
}
match = nil
policies.each {|p|
    if p['id'].to_i == pid.to_i
      #puts("#{pid} - #{p['name']} is valid")
      match = pid
      next
    end
}
if match.nil?
    puts("No Matching Policy ID: #{pid}")
    exit
end

#start scan
uri = "scan/new"
post_data = { "token" => @token, "policy_id" => options[:policy], "scan_name" => options[:name], "target" => options[:target] }
stuff = @n.connect(uri, post_data)
docxml = REXML::Document.new(stuff)
uuid=docxml.root.elements['contents'].elements['scan'].elements['uuid'].text

#loop checking scan, print %done if -v
done = false
print "Running Scan"
while done == false
    uri = "scan/list"
    post_data = { "token" => @token }
    stuff = @n.connect(uri, post_data)
    docxml = REXML::Document.new(stuff)
    docxml.elements.each('/reply/contents/scans/scanList/scan') {|scan|
      if scan.elements['uuid'].text == uuid
        if scan.elements['status'].text == "running"
          now = scan.elements['completion_current'].text
          total = scan.elements['completion_total'].text
          percent = (now.to_f / total.to_f) * 100
          print "\r\e"
          print(" Scan is #{percent.round(2)}% done.")
          sleep 1
        else
          puts("Scan complete.")
          done = true
          exit
        end
      end
    }
end


# scan done, get report

#parse report into ivil

#output



