// Code generated by mockery v2.20.0. DO NOT EDIT.

package mocks

import (
	context "context"

	biz "github.com/chainloop-dev/chainloop/app/controlplane/pkg/biz"

	dsse "github.com/secure-systems-lab/go-securesystemslib/dsse"

	mock "github.com/stretchr/testify/mock"

	pagination "github.com/chainloop-dev/chainloop/app/controlplane/internal/pagination"

	time "time"

	uuid "github.com/google/uuid"
)

// WorkflowRunRepo is an autogenerated mock type for the WorkflowRunRepo type
type WorkflowRunRepo struct {
	mock.Mock
}

// Create provides a mock function with given fields: ctx, opts
func (_m *WorkflowRunRepo) Create(ctx context.Context, opts *biz.WorkflowRunRepoCreateOpts) (*biz.WorkflowRun, error) {
	ret := _m.Called(ctx, opts)

	var r0 *biz.WorkflowRun
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *biz.WorkflowRunRepoCreateOpts) (*biz.WorkflowRun, error)); ok {
		return rf(ctx, opts)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *biz.WorkflowRunRepoCreateOpts) *biz.WorkflowRun); ok {
		r0 = rf(ctx, opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*biz.WorkflowRun)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *biz.WorkflowRunRepoCreateOpts) error); ok {
		r1 = rf(ctx, opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Expire provides a mock function with given fields: ctx, id
func (_m *WorkflowRunRepo) Expire(ctx context.Context, id uuid.UUID) error {
	ret := _m.Called(ctx, id)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) error); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FindByAttestationDigest provides a mock function with given fields: ctx, digest
func (_m *WorkflowRunRepo) FindByAttestationDigest(ctx context.Context, digest string) (*biz.WorkflowRun, error) {
	ret := _m.Called(ctx, digest)

	var r0 *biz.WorkflowRun
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*biz.WorkflowRun, error)); ok {
		return rf(ctx, digest)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *biz.WorkflowRun); ok {
		r0 = rf(ctx, digest)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*biz.WorkflowRun)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, digest)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindByID provides a mock function with given fields: ctx, ID
func (_m *WorkflowRunRepo) FindByID(ctx context.Context, ID uuid.UUID) (*biz.WorkflowRun, error) {
	ret := _m.Called(ctx, ID)

	var r0 *biz.WorkflowRun
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) (*biz.WorkflowRun, error)); ok {
		return rf(ctx, ID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) *biz.WorkflowRun); ok {
		r0 = rf(ctx, ID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*biz.WorkflowRun)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID) error); ok {
		r1 = rf(ctx, ID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindByIDInOrg provides a mock function with given fields: ctx, orgID, ID
func (_m *WorkflowRunRepo) FindByIDInOrg(ctx context.Context, orgID uuid.UUID, ID uuid.UUID) (*biz.WorkflowRun, error) {
	ret := _m.Called(ctx, orgID, ID)

	var r0 *biz.WorkflowRun
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, uuid.UUID) (*biz.WorkflowRun, error)); ok {
		return rf(ctx, orgID, ID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, uuid.UUID) *biz.WorkflowRun); ok {
		r0 = rf(ctx, orgID, ID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*biz.WorkflowRun)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID, uuid.UUID) error); ok {
		r1 = rf(ctx, orgID, ID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// List provides a mock function with given fields: ctx, orgID, f, p
func (_m *WorkflowRunRepo) List(ctx context.Context, orgID uuid.UUID, f *biz.RunListFilters, p *pagination.CursorOptions) ([]*biz.WorkflowRun, string, error) {
	ret := _m.Called(ctx, orgID, f, p)

	var r0 []*biz.WorkflowRun
	var r1 string
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, *biz.RunListFilters, *pagination.CursorOptions) ([]*biz.WorkflowRun, string, error)); ok {
		return rf(ctx, orgID, f, p)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, *biz.RunListFilters, *pagination.CursorOptions) []*biz.WorkflowRun); ok {
		r0 = rf(ctx, orgID, f, p)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*biz.WorkflowRun)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID, *biz.RunListFilters, *pagination.CursorOptions) string); ok {
		r1 = rf(ctx, orgID, f, p)
	} else {
		r1 = ret.Get(1).(string)
	}

	if rf, ok := ret.Get(2).(func(context.Context, uuid.UUID, *biz.RunListFilters, *pagination.CursorOptions) error); ok {
		r2 = rf(ctx, orgID, f, p)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// ListNotFinishedOlderThan provides a mock function with given fields: ctx, olderThan
func (_m *WorkflowRunRepo) ListNotFinishedOlderThan(ctx context.Context, olderThan time.Time) ([]*biz.WorkflowRun, error) {
	ret := _m.Called(ctx, olderThan)

	var r0 []*biz.WorkflowRun
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, time.Time) ([]*biz.WorkflowRun, error)); ok {
		return rf(ctx, olderThan)
	}
	if rf, ok := ret.Get(0).(func(context.Context, time.Time) []*biz.WorkflowRun); ok {
		r0 = rf(ctx, olderThan)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*biz.WorkflowRun)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, time.Time) error); ok {
		r1 = rf(ctx, olderThan)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MarkAsFinished provides a mock function with given fields: ctx, ID, status, reason
func (_m *WorkflowRunRepo) MarkAsFinished(ctx context.Context, ID uuid.UUID, status biz.WorkflowRunStatus, reason string) error {
	ret := _m.Called(ctx, ID, status, reason)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, biz.WorkflowRunStatus, string) error); ok {
		r0 = rf(ctx, ID, status, reason)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SaveAttestation provides a mock function with given fields: ctx, ID, att, digest
func (_m *WorkflowRunRepo) SaveAttestation(ctx context.Context, ID uuid.UUID, att *dsse.Envelope, digest string) error {
	ret := _m.Called(ctx, ID, att, digest)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, *dsse.Envelope, string) error); ok {
		r0 = rf(ctx, ID, att, digest)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTNewWorkflowRunRepo interface {
	mock.TestingT
	Cleanup(func())
}

// NewWorkflowRunRepo creates a new instance of WorkflowRunRepo. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewWorkflowRunRepo(t mockConstructorTestingTNewWorkflowRunRepo) *WorkflowRunRepo {
	mock := &WorkflowRunRepo{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}