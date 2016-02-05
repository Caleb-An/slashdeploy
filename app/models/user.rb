# User represents a user of SlashDeploy.
class User < ActiveRecord::Base
  has_many :github_accounts
  has_many :slack_accounts

  def self.find_by_slack(id)
    account = SlackAccount.where(id: id).first
    return unless account
    account.user
  end

  def self.find_by_github(id)
    account = GithubAccount.where(id: id).first
    return unless account
    account.user
  end

  def slack_account?(slack_account)
    slack_accounts.find do |account|
      account.id == slack_account.id
    end
  end

  def github_account?(github_account)
    github_accounts.find do |account|
      account.id == github_account.id
    end
  end

  def slack_username(team_id)
    account = slack_accounts.find { |a| a.team_id == team_id }
    return unless account
    account.user_name
  end
end
