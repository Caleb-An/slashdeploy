# SlashCommands is a slash handler that provides the SlashDeploy slack slash
# commands. This class simply a demuxer that routes requests to the appropriate
# sub command.
class SlashCommands
  attr_reader \
    :help,
    :deploy,
    :environments,
    :lock,
    :unlock

  def initialize(slashdeploy)
    @help = HelpCommand.new slashdeploy
    @deploy = DeployCommand.new slashdeploy
    @environments = EnvironmentsCommand.new slashdeploy
    @lock = LockCommand.new slashdeploy
    @unlock = UnlockCommand.new slashdeploy
  end

  # Route returns the handler that should handle the request.
  def route(cmd)
    repo = /(?<repository>#{SlashDeploy::GITHUB_REPO_REGEX})/
    env  = /(?<environment>\S+?)/
    ref  = /(?<ref>\S+?)/

    case cmd.request.text
    when /^help$/
      [help, {}]
    when /^where #{repo}$/
      [environments, params(Regexp.last_match)]
    when /^lock #{env} on #{repo}(:(?<message>.*))?$/
      [lock, params(Regexp.last_match)]
    when /^unlock #{env} on #{repo}$/
      [unlock, params(Regexp.last_match)]
    when /^#{repo}(@#{ref})?( to #{env})?(?<force>!)?$/
      [deploy, params(Regexp.last_match)]
    end
  end

  def call(env)
    cmd  = env['cmd']
    user = env['user']

    handler, params = route(cmd)
    handler.run(user, cmd, params)
  end

  private

  def match_repository
  end

  def params(matches)
    Hash[matches.names.zip(matches.captures)]
  end
end
