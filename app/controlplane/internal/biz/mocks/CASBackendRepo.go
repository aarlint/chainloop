// Code generated by mockery v2.20.0. DO NOT EDIT.

package mocks

import (
	context "context"

	biz "github.com/chainloop-dev/chainloop/app/controlplane/internal/biz"

	mock "github.com/stretchr/testify/mock"

	uuid "github.com/google/uuid"
)

// CASBackendRepo is an autogenerated mock type for the CASBackendRepo type
type CASBackendRepo struct {
	mock.Mock
}

// Create provides a mock function with given fields: _a0, _a1
func (_m *CASBackendRepo) Create(_a0 context.Context, _a1 *biz.CASBackendCreateOpts) (*biz.CASBackend, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *biz.CASBackend
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *biz.CASBackendCreateOpts) (*biz.CASBackend, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *biz.CASBackendCreateOpts) *biz.CASBackend); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*biz.CASBackend)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *biz.CASBackendCreateOpts) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Delete provides a mock function with given fields: ctx, ID
func (_m *CASBackendRepo) Delete(ctx context.Context, ID uuid.UUID) error {
	ret := _m.Called(ctx, ID)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) error); ok {
		r0 = rf(ctx, ID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FindByID provides a mock function with given fields: ctx, ID
func (_m *CASBackendRepo) FindByID(ctx context.Context, ID uuid.UUID) (*biz.CASBackend, error) {
	ret := _m.Called(ctx, ID)

	var r0 *biz.CASBackend
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) (*biz.CASBackend, error)); ok {
		return rf(ctx, ID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) *biz.CASBackend); ok {
		r0 = rf(ctx, ID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*biz.CASBackend)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID) error); ok {
		r1 = rf(ctx, ID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindByIDInOrg provides a mock function with given fields: ctx, OrgID, ID
func (_m *CASBackendRepo) FindByIDInOrg(ctx context.Context, OrgID uuid.UUID, ID uuid.UUID) (*biz.CASBackend, error) {
	ret := _m.Called(ctx, OrgID, ID)

	var r0 *biz.CASBackend
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, uuid.UUID) (*biz.CASBackend, error)); ok {
		return rf(ctx, OrgID, ID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, uuid.UUID) *biz.CASBackend); ok {
		r0 = rf(ctx, OrgID, ID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*biz.CASBackend)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID, uuid.UUID) error); ok {
		r1 = rf(ctx, OrgID, ID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindDefaultBackend provides a mock function with given fields: ctx, orgID
func (_m *CASBackendRepo) FindDefaultBackend(ctx context.Context, orgID uuid.UUID) (*biz.CASBackend, error) {
	ret := _m.Called(ctx, orgID)

	var r0 *biz.CASBackend
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) (*biz.CASBackend, error)); ok {
		return rf(ctx, orgID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) *biz.CASBackend); ok {
		r0 = rf(ctx, orgID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*biz.CASBackend)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID) error); ok {
		r1 = rf(ctx, orgID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// List provides a mock function with given fields: ctx, orgID
func (_m *CASBackendRepo) List(ctx context.Context, orgID uuid.UUID) ([]*biz.CASBackend, error) {
	ret := _m.Called(ctx, orgID)

	var r0 []*biz.CASBackend
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) ([]*biz.CASBackend, error)); ok {
		return rf(ctx, orgID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) []*biz.CASBackend); ok {
		r0 = rf(ctx, orgID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*biz.CASBackend)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID) error); ok {
		r1 = rf(ctx, orgID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Update provides a mock function with given fields: _a0, _a1
func (_m *CASBackendRepo) Update(_a0 context.Context, _a1 *biz.CASBackendUpdateOpts) (*biz.CASBackend, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *biz.CASBackend
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *biz.CASBackendUpdateOpts) (*biz.CASBackend, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *biz.CASBackendUpdateOpts) *biz.CASBackend); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*biz.CASBackend)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *biz.CASBackendUpdateOpts) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateValidationStatus provides a mock function with given fields: ctx, ID, status
func (_m *CASBackendRepo) UpdateValidationStatus(ctx context.Context, ID uuid.UUID, status biz.CASBackendValidationStatus) error {
	ret := _m.Called(ctx, ID, status)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, biz.CASBackendValidationStatus) error); ok {
		r0 = rf(ctx, ID, status)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTNewCASBackendRepo interface {
	mock.TestingT
	Cleanup(func())
}

// NewCASBackendRepo creates a new instance of CASBackendRepo. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewCASBackendRepo(t mockConstructorTestingTNewCASBackendRepo) *CASBackendRepo {
	mock := &CASBackendRepo{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
