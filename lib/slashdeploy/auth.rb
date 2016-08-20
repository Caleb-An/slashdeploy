module SlashDeploy
  # Auth is a slash handler middeware that authenticates the Slack user with GitHub.
  class Auth
    attr_reader :handler
    attr_reader :client
    attr_reader :state_encoder

    def initialize(handler, oauth_client, state_encoder)
      @handler = handler
      @client = oauth_client
      @state_encoder = state_encoder
    end

    def call(env)
      case env['type']
      when 'cmd'
        auth_data = env['cmd']
      when 'action'
        auth_data = env['action']
      end

      # Attempt to find the user by their slack user id. This is sufficient
      # to authenticate the user, because we're trusting that the request is
      # coming from Slack.
      account = SlackAccount.find_or_create_from_command_payload(auth_data)
      unless account.user
        account.user = User.new
        account.save!
      end

      env['user'] = SlackUser.new(account.user, account.slack_team)

      begin
        handler.call(env)
      rescue User::MissingGitHubAccount
        # If we don't know this slack user, we'll ask them to authenticate
        # with GitHub. We encode and sign the Slack user id within the state
        # param so we know what slack user they are when the hit the GitHub
        # callback.
        state = state_encoder.encode(user_id: account.user.id)
        url = client.auth_code.authorize_url(state: state, scope: 'repo_deployment')
        Slash.reply(Slack::Message.new(text: "I don't know who you are on GitHub yet. Please <#{url}|authenticate> then try again."))
      end
    end
  end
end
