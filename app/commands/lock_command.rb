# LockCommand handles the `/deploy lock` command.
class LockCommand < BaseCommand
  def run(slack_user, _cmd, params)
    transaction do
      repo = Repository.with_name(params['repository'])
      env  = repo.environment(params['environment'])
      resp = slashdeploy.lock_environment(slack_user.user, env, params['message'].try(:strip))
      if resp
        stealer = resp.stolen ? SlackUser.new(resp.stolen.user, slack_user.slack_team) : nil
        say :locked, environment: env, repository: repo, stealer: stealer
      else
        say :already_locked, environment: env, repository: repo
      end
    end
  end
end
