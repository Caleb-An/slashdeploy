module SlashDeploy
  # SlashDeploy::Service provides the core internal API for controllers to
  # consume. This composes the various backends and provides a very simple API
  # for performing actions.
  class Service
    attr_accessor :github_client

    # An object that responds to `call` where the first argument is a User
    # object. Should return something that implements the Deployer interface.
    attr_accessor :deployer

    # Creates a new deployment request as the given user.
    #
    # user        - The User requesting the deployment.
    # environment - The Environment to be deployed to.
    # ref         - A String git ref. If none is provided, defaults to the
    #               default ref.
    # options     - A Hash of extra options.
    #               :force       - "force" the deployment, ignoring commit
    #                               status contexts.
    #               :strong_lock - If set to true, even the user that locked it
    #                              won't be able to deploy.
    #
    # Returns a DeploymentResponse.
    def create_deployment(user, environment, ref = nil, options = {})
      req = deployment_request(environment, ref, force: options[:force])

      # Check if the environment we're deploying to is configured for auto deployments.
      fail EnvironmentAutoDeploys if environment.auto_deploy_enabled? && !options[:force]

      # Check if the environment we're deploying to is locked.
      lock = environment.active_lock
      if lock && lock.user != user
        fail EnvironmentLockedError, lock
      else
        deployer.create_deployment(user, req)
      end
    end

    # Returns the known environments that this repository can be deployed to.
    #
    # repository - The name of the repository.
    #
    # Returns an Array of Environments
    def environments(user, repository)
      authorize! user, repository
      repository.environments
    end

    # Attempts to lock the environment on the repo.
    #
    # environment - An Environment to lock.
    # message     - An option message.
    #
    # Returns a Lock.
    def lock_environment(user, environment, message = nil)
      authorize! user, environment.repository

      lock = environment.active_lock

      if lock
        return if lock.user == user # Already locked, nothing to do.
        lock.unlock!
      end

      stolen = lock
      lock = environment.lock! user, message

      LockResponse.new \
        lock: lock,
        stolen: stolen
    end

    # Unlocks an environment.
    #
    # environment - An Environment to unlock
    #
    # Returns nothing
    def unlock_environment(user, environment)
      authorize! user, environment.repository

      lock = environment.active_lock
      return unless lock
      lock.unlock!
    end

    # Triggers an auto deployment if the AutoDeployment is ready.
    #
    # auto_deployment - An AutoDeployment.
    #
    # Returns nothing.
    def auto_deploy(auto_deployment)
      return unless auto_deployment.ready?

      begin
        environment = auto_deployment.environment

        # Check if the environment we're deploying to is locked.
        return if environment.locked?
        deployer.create_deployment(auto_deployment.user, deployment_request(environment, auto_deployment.sha))
      ensure
        auto_deployment.done!
      end
    end

    private

    def deployment_request(environment, ref, options = {})
      DeploymentRequest.new(
        repository:  environment.repository.to_s,
        environment: environment.to_s,
        ref:         ref || environment.default_ref,
        force:       options[:force]
      )
    end

    def authorize!(user, repository)
      fail RepoUnauthorized, repository unless github_client.access?(user, repository.to_s)
    end
  end
end
