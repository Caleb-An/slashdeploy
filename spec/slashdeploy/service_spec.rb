require 'rails_helper'

RSpec.describe SlashDeploy::Service do
  fixtures :users

  let(:github) { double(GitHub::Client, access?: true) }
  let(:service) do
    described_class.new.tap do |service|
      service.github = github
    end
  end

  describe '#create_deployment' do
    context 'when no environment or ref is provided' do
      it 'sets the default environment' do
        repo = stub_model(Repository, name: 'remind101/acme-inc')
        env  = stub_model(Environment, repository: repo, name: 'production', active_lock: nil)
        expect(github).to receive(:access?).with(users(:david), 'remind101/acme-inc').and_return(true)
        expect(github).to receive(:last_deployment).with(users(:david), 'remind101/acme-inc', 'production').and_return(nil)
        expect(github).to receive(:create_deployment).with(
          users(:david),
          DeploymentRequest.new(
            repository: 'remind101/acme-inc',
            environment: 'production',
            ref: 'master'
          )
        )
        resp = service.create_deployment(users(:david), env, 'master')
        expect(resp).to be_a(DeploymentResponse)
      end
    end

    context 'when the environment is locked' do
      it 'raises an exception' do
        repo = stub_model(Repository, name: 'remind101/acme-inc')
        lock = stub_model(Lock, user: users(:david))
        env  = stub_model(Environment, repository: repo, name: 'production', active_lock: lock)
        expect do
          service.create_deployment(users(:steve), env, 'master')
        end.to raise_exception SlashDeploy::EnvironmentLockedError
      end
    end
  end

  describe '#lock_environment' do
    context 'when there is no existing lock' do
      it 'locks the environment' do
        repo = stub_model(Repository, name: 'remind101/acme-inc')
        env  = stub_model(Environment, repository: repo, name: 'staging', active_lock: nil)
        expect(github).to receive(:access?).with(users(:david), 'remind101/acme-inc').and_return(true)
        expect(env).to receive(:lock!).with(users(:david), 'Testing some stuff')
        service.lock_environment(users(:david), env, 'Testing some stuff')
      end
    end

    context 'when there is an existing lock held by a different user' do
      it 'locks the environment' do
        repo = stub_model(Repository, name: 'remind101/acme-inc')
        lock = stub_model(Lock, user: users(:steve))
        env  = stub_model(Environment, repository: repo, name: 'staging', active_lock: lock)
        expect(github).to receive(:access?).with(users(:david), 'remind101/acme-inc').and_return(true)
        expect(lock).to receive(:unlock!)
        expect(env).to receive(:lock!).with(users(:david), 'Testing some stuff')
        resp = service.lock_environment(users(:david), env, 'Testing some stuff')
        expect(resp.stolen).to eq lock
      end
    end

    context 'when there is an existing lock held by the same user' do
      it 'returns nil' do
        repo = stub_model(Repository, name: 'remind101/acme-inc')
        lock = stub_model(Lock, user: users(:david))
        env  = stub_model(Environment, repository: repo, name: 'staging', active_lock: lock)
        expect(github).to receive(:access?).with(users(:david), 'remind101/acme-inc').and_return(true)
        resp = service.lock_environment(users(:david), env, 'Testing some stuff')
        expect(resp).to be_nil
      end
    end
  end

  describe '#unlock_environment' do
    context 'when the environment is locked by a different user' do
      it 'unlocks it' do
        repo = stub_model(Repository, name: 'remind101/acme-inc')
        env  = stub_model(Environment, repository: repo, name: 'staging', active_lock: nil)
        expect(github).to receive(:access?).with(users(:david), 'remind101/acme-inc').and_return(true)
        expect(env).to receive(:lock!).with(users(:david), 'Testing some stuff')
        service.lock_environment(users(:david), env, 'Testing some stuff')
      end
    end
  end

  describe '#environments' do
    it 'returns the environments' do
      repo = stub_model(Repository, name: 'remind101/acme-inc', environments: [])
      expect(github).to receive(:access?).with(users(:david), 'remind101/acme-inc').and_return(true)
      service.environments(users(:david), repo)
    end
  end
end
