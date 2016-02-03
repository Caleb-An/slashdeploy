module SlashDeploy
  # SlashDeploy::Service provides the core internal API for controllers to
  # consume. This composes the various backends and provides a very simple API
  # for performing actions.
  class Service
    # An object that responds to `call` where the first argument is a User
    # object. Should return something that implements the Deployer interface.
    attr_accessor :deployer

    # Creates a new deployment request as the given user.
    #
    # req - DeploymentRequest object.
    #
    # Returns the id of the created Deployment.
    def create_deployment(user, req)
      req = DeploymentRequest.new(
        repository: req.repository,
        environment: req.environment || config.default_environment,
        ref: req.ref || config.default_ref
      )

      deployer = self.deployer.call(user)
      Environment.used(req.repository, req.environment)
      deployer.create_deployment(req)
      req
    end

    # Returns the known environments that this repository can be deployed to.
    #
    # repository - The name of the repository.
    #
    # Returns an Array of Environments
    def environments(_user, repository)
      # TODO: Authorize that this user has access to the repository.
      Environment.where(repository: repository)
    end

    private

    def config
      Rails.configuration.x
    end
  end
end
