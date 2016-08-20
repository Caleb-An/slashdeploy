# SlackAccount represents a connected Slack account.
class SlackAccount < ActiveRecord::Base
  belongs_to :user
  belongs_to :slack_team

  def self.create_from_auth_hash(auth_hash)
    team = SlackTeam.find_or_initialize_by(id: auth_hash[:info][:team_id]) do |t|
      t.domain = auth_hash[:info][:team_domain]
    end

    create! \
      id: auth_hash[:uid],
      user_name: auth_hash[:info][:nickname],
      slack_team: team
  end

  def self.find_or_create_from_command_payload(payload)
    SlackAccount.find_by_id(payload.user_id) || create_from_command_payload(payload)
  end

  def self.create_from_command_payload(payload)
    team = SlackTeam.find_or_initialize_by(id: payload.team_id) do |t|
      t.domain = payload.team_domain
    end

    create! \
      id:         payload.user_id,
      user_name:  payload.user_name,
      slack_team: team
  end

  def team_id
    slack_team.id
  end

  def team_domain
    slack_team.domain
  end

  def bot_access_token
    slack_team.bot_access_token
  end
end
