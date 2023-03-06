// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package testhelpers

import (
	"github.com/chainloop-dev/bedrock/app/controlplane/internal/biz"
	"github.com/chainloop-dev/bedrock/app/controlplane/internal/conf"
	"github.com/chainloop-dev/bedrock/app/controlplane/internal/data"
	"github.com/chainloop-dev/bedrock/internal/blobmanager/oci"
	"github.com/chainloop-dev/bedrock/internal/credentials"
	"github.com/chainloop-dev/bedrock/internal/robotaccount/cas"
	"github.com/go-kratos/kratos/v2/log"
	"testing"
)

import (
	_ "github.com/lib/pq"
)

// Injectors from wire.go:

// wireTestData init testing data
func WireTestData(testDatabase *TestDatabase, t *testing.T, logger log.Logger, readerWriter credentials.ReaderWriter, builder *robotaccount.Builder, auth *conf.Auth) (*TestingUseCases, func(), error) {
	confData := newConfData(testDatabase, t)
	dataData, cleanup, err := data.NewData(confData, logger)
	if err != nil {
		return nil, nil, err
	}
	membershipRepo := data.NewMembershipRepo(dataData, logger)
	membershipUseCase := biz.NewMembershipUsecase(membershipRepo, logger)
	ociRepositoryRepo := data.NewOCIRepositoryRepo(dataData, logger)
	backendProvider := oci.NewBackendProvider(readerWriter)
	ociRepositoryUseCase := biz.NewOCIRepositoryUsecase(ociRepositoryRepo, readerWriter, backendProvider, logger)
	integrationRepo := data.NewIntegrationRepo(dataData, logger)
	integrationAttachmentRepo := data.NewIntegrationAttachmentRepo(dataData, logger)
	workflowRepo := data.NewWorkflowRepo(dataData, logger)
	newIntegrationUsecaseOpts := &biz.NewIntegrationUsecaseOpts{
		IRepo:   integrationRepo,
		IaRepo:  integrationAttachmentRepo,
		WfRepo:  workflowRepo,
		CredsRW: readerWriter,
		Logger:  logger,
	}
	integrationUseCase := biz.NewIntegrationUsecase(newIntegrationUsecaseOpts)
	organizationRepo := data.NewOrganizationRepo(dataData, logger)
	organizationUseCase := biz.NewOrganizationUsecase(organizationRepo, ociRepositoryUseCase, integrationUseCase, logger)
	workflowContractRepo := data.NewWorkflowContractRepo(dataData, logger)
	workflowContractUseCase := biz.NewWorkflowContractUsecase(workflowContractRepo, logger)
	workflowUseCase := biz.NewWorkflowUsecase(workflowRepo, workflowContractUseCase, logger)
	workflowRunRepo := data.NewWorkflowRunRepo(dataData, logger)
	workflowRunUseCase, err := biz.NewWorkflowRunUsecase(workflowRunRepo, workflowRepo, logger)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	userRepo := data.NewUserRepo(dataData, logger)
	newUserUseCaseParams := &biz.NewUserUseCaseParams{
		UserRepo:            userRepo,
		MembershipUseCase:   membershipUseCase,
		OrganizationUseCase: organizationUseCase,
		Logger:              logger,
	}
	userUseCase := biz.NewUserUseCase(newUserUseCaseParams)
	robotAccountRepo := data.NewRobotAccountRepo(dataData, logger)
	robotAccountUseCase := biz.NewRootAccountUseCase(robotAccountRepo, workflowRepo, auth, logger)
	testingUseCases := &TestingUseCases{
		DB:               testDatabase,
		L:                logger,
		Membership:       membershipUseCase,
		OCIRepo:          ociRepositoryUseCase,
		Integration:      integrationUseCase,
		Organization:     organizationUseCase,
		WorkflowContract: workflowContractUseCase,
		Workflow:         workflowUseCase,
		WorkflowRun:      workflowRunUseCase,
		User:             userUseCase,
		RobotAccount:     robotAccountUseCase,
	}
	return testingUseCases, func() {
		cleanup()
	}, nil
}
