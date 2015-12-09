package commands

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ejholmes/slash"
	"github.com/ejholmes/slashdeploy"
	"github.com/ejholmes/slashdeploy/deployments"
	"golang.org/x/net/context"
)

// Defaults unless overriden by the repository settings.
var (
	DefaultEnvironment = "production"
	DefaultRef         = "master"
)

// InvalidRepoError is an error implementation used to represent an invalid
// GitHub repository.
type InvalidRepoError struct {
	Repository string
}

func (e *InvalidRepoError) Error() string {
	return fmt.Sprintf("%s is not a valid repository", e.Repository)
}

type deploymentsService interface {
	CreateDeployment(context.Context, slashdeploy.DeploymentRequest) (*slashdeploy.Deployment, error)
}

// Deploy is a slash.Handler that triggers a deployment using the deployments
// service.
type Deploy struct {
	deploymentsService
}

func NewDeploy(s *deployments.Service) *Deploy {
	return &Deploy{
		deploymentsService: s,
	}
}

func (c *Deploy) ServeCommand(ctx context.Context, r slash.Responder, _ slash.Command) (slash.Response, error) {
	params := slash.Params(ctx)

	req, err := deploymentRequest(params)
	if err != nil {
		return slash.NoResponse, err
	}

	_, err = c.CreateDeployment(ctx, req)
	if err != nil {
		return slash.NoResponse, err
	}

	return slash.Say(fmt.Sprintf("Created deployment request for %s.", req)), nil
}

func deploymentRequest(params map[string]string) (slashdeploy.DeploymentRequest, error) {
	var d slashdeploy.DeploymentRequest

	// Parse the <org>/<repo> format into it's individual parts, returning
	// an error if it's not a valid repo.
	var ok bool
	d.Owner, d.Repository, ok = splitRepo(params["repo"])
	if !ok {
		return d, &InvalidRepoError{Repository: params["repo"]}
	}

	d.Environment = params["environment"]
	d.Ref = params["ref"]

	return d, nil
}

// errInvalidRepo is returned by splitRepo if the string is not a valid GitHub
// repositor.y
var errInvalidRepo = errors.New("repo not valid")

// splitRepo splits the <org>/<repo> format into <org> and <repo> parts.
func splitRepo(fullName string) (repo, owner string, ok bool) {
	parts := strings.SplitN(fullName, "/", 2)
	if len(parts) != 2 {
		return
	}

	ok = true
	repo, owner = parts[0], parts[1]

	return
}
