# The primary controller that all controllers inherit from.
class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
  before_filter :sign_in_from_state

  def current_user
    warden.user
  end
  helper_method :current_user

  def signed_in?
    warden.authenticated?
  end
  helper_method :signed_in?

  private

  def sign_in_from_state
    if state = params[:auth_state].presence
      decoded_state = SlashDeploy.state.decode(state)
      user = User.find(decoded_state['user_id'])
      warden.set_user user
    end
  end

  def warden
    request.env['warden']
  end
end
