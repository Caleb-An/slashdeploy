require 'rails_helper'

RSpec.describe GithubEventHandler do
  let(:slashdeploy) { double(SlashDeploy::Service) }
  let(:handler) do
    Class.new(GithubEventHandler) do
      attr_reader :repository, :event

      def run(repository, event)
        @repository = repository
        @event = event
      end
    end.new slashdeploy
  end

  describe '#call' do
    context 'when the repo is not found' do
      # This should never actually happen. If it does, it means something is
      # misconfigured.
      it 'raises an error' do
        req = Rack::MockRequest.new(handler)
        expect do
          req.post \
            '/',
            input: {
              repository: {
                full_name: 'remind101/acme-inc'
              }
            }.to_json,
            'CONTENT_TYPE' => 'application/json'
        end.to raise_error GithubEventHandler::UnknownRepository
      end
    end

    context 'when the signature does not match' do
      it 'returns a 403' do
        Repository.create!(name: 'remind101/acme-inc', github_secret: 'secret')
        req = Rack::MockRequest.new(handler)
        resp = req.post \
          '/',
          input: {
            repository: {
              full_name: 'remind101/acme-inc'
            }
          }.to_json,
          'CONTENT_TYPE' => 'application/json',
          'HTTP_X_HUB_SIGNATURE' => 'sha1=abcd'
        expect(resp.status).to eq 403
      end
    end

    context 'when the signature matches' do
      it 'returns a 200 and calls the handler' do
        repo = Repository.create!(name: 'remind101/acme-inc', github_secret: 'secret')
        req = Rack::MockRequest.new(handler)
        resp = req.post \
          '/',
          input: {
            repository: {
              full_name: 'remind101/acme-inc'
            }
          }.to_json,
          'CONTENT_TYPE' => 'application/json',
          'HTTP_X_HUB_SIGNATURE' => 'sha1=692ed45ae7de94533457e9d4931389f02a189e1f'
        expect(resp.status).to eq 200
        expect(handler.repository).to eq repo
        expect(handler.event['repository']['full_name']).to eq 'remind101/acme-inc'
      end
    end
  end
end
