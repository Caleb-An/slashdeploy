SlashDeploy.service.deployer = case Rails.configuration.x.deployer
                               when 'github'
                                 SlashDeploy::Deployer::GitHub 
                               else
                                 SlashDeploy::Deployer::Fake
                               end

# Used to encode and sign the oauth state param for keeping track of a slack
# user id across github authentication.
SlashDeploy.state = SlashDeploy::State.new Rails.configuration.x.state_key
