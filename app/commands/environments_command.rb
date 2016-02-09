# EnvironmentsCommand handles the `/deploy where` subcommand.
class EnvironmentsCommand < BaseCommand
  def run(user, _cmd, params)
    transaction do
      repo = Repository.with_name(params['repository'])
      environments = slashdeploy.environments(user, repo)
      say :list, repository: repo, environments: environments
    end
  end
end
