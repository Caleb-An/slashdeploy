class SlackTeam < ActiveRecord::Base
  has_many :slack_accounts
end
