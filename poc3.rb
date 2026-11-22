# Arm 2: is GitHub's internal network ROUTABLE from a Pages build container?
#
# This asks the exact question the *.github.net ineligible row poses. Its words:
#   "Some public DNS records resolve to RFC 1918 or otherwise internal addresses.
#    On its own this tells an attacker nothing they can act on, BECAUSE THEY STILL
#    CANNOT ROUTE TO THOSE HOSTS. These reports are ineligible unless you pair them
#    with a working path to reach the address, such as a server side request forgery
#    that we can reproduce."
# Arm 1 established the precondition: this container resolves through the AWS VPC
# resolver at 10.0.0.2, not a public one.
#
# BOUNDS:
#   - Hostnames are taken from prior recon already recorded on disk. NONE is guessed,
#     and no name is enumerated or mutated. Eight names, chosen as a spread.
#   - One DNS query per name. A TCP connect is attempted ONLY where the name resolves
#     into private address space - the connect arm is gated on the resolution, so
#     nothing public and nothing nonexistent is touched.
#   - CONNECT AND CLOSE ONLY. No TLS handshake, no HTTP request, no bytes written, no
#     bytes read, no retry, 3s timeout. Routability is the whole question.
#   - No credential is read or sent anywhere.

require "socket"
require "resolv"
require "timeout"

OUT = []
def say(s) OUT << s end

def private_ip?(ip)
  return false unless ip =~ /\A\d+\.\d+\.\d+\.\d+\z/
  a, b, = ip.split(".").map(&:to_i)
  return true if a == 10 || a == 127
  return true if a == 172 && b.between?(16, 31)
  return true if a == 192 && b == 168
  return true if a == 169 && b == 254
  return true if a == 100 && b.between?(64, 127)
  false
end

def resolve(h)
  Timeout.timeout(3) { Resolv.getaddresses(h) }
rescue Exception => e
  ["ERR:#{e.class}"]
end

def connect_once(ip, port)
  Timeout.timeout(3) do
    s = TCPSocket.new(ip, port)
    s.close              # nothing written, nothing read
    "ROUTABLE"
  end
rescue Exception => e
  e.class.to_s
end

# documented names, from recon already on disk
NAMES = %w[
  logging.service.github.net
  ldap-provider.service.github.net
  ops-consul1-pe1-prd.aws.github.net
  kube-me.aws.github.net
  lfs.aws.github.net
  mirrors.github.net
  iad.github.net
  breadsticks.kube-service.github.net
]

BOGUS = %w[
  nx-4b81e07a-nothing.github.net
  nx-4b81e07a-nothing.aws.github.net
]

say "== resolver in use =="
say "  " + (File.read("/etc/resolv.conf").split("\n").grep(/nameserver|search/).join(" ; ") rescue "?")

say "== CONTROL: can this process connect into PRIVATE address space at all? =="
say "  169.254.169.254:80 -> #{connect_once('169.254.169.254', 80)}"
say "  (link-local, named expected-reachable by GitHub. If this is ROUTABLE, then a"
say "   refusal below is unroutability and not a broken connect primitive.)"

say "== CONTROL: names that must NOT resolve =="
BOGUS.each { |b| say "  #{b} -> #{resolve(b).first(2).join(',')}" }

say "== documented *.github.net names =="
private_hits = 0
NAMES.each do |h|
  ips = resolve(h)
  real = ips.reject { |i| i.to_s.start_with?("ERR:") }
  if real.empty?
    say "  #{h}"
    say "      dns=#{ips.first(2).join(',')}  -> no address, nothing to connect to"
    next
  end
  priv = real.select { |i| private_ip?(i) }
  say "  #{h}"
  say "      dns=#{real.first(3).join(',')}  private=#{!priv.empty?}"
  if priv.empty?
    say "      connect SKIPPED: resolves public, so not an internal-network question"
  else
    private_hits += 1
    ip = priv.first
    say "      connect #{ip}:443 -> #{connect_once(ip, 443)}"
    say "      connect #{ip}:80  -> #{connect_once(ip, 80)}"
  end
end

say "== TALLY =="
say "  names resolving into private space: #{private_hits} of #{NAMES.length}"
say "== END =="

body = OUT.join("\n")
begin
  File.write("/github/workspace/INTERNAL.txt", body + "\n")
rescue Exception
end
STDERR.puts "F007_INTERNAL_BEGIN\n" + body + "\nF007_INTERNAL_END"
raise "F007_INTERNAL_PROBE_DONE"
