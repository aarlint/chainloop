//
// Copyright 2023 The Chainloop Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by mockery v2.20.0. DO NOT EDIT.

package mocks

import (
	context "context"
	io "io"

	mock "github.com/stretchr/testify/mock"
)

// Downloader is an autogenerated mock type for the Downloader type
type Downloader struct {
	mock.Mock
}

// Download provides a mock function with given fields: ctx, w, digest
func (_m *Downloader) Download(ctx context.Context, w io.Writer, digest string) error {
	ret := _m.Called(ctx, w, digest)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, io.Writer, string) error); ok {
		r0 = rf(ctx, w, digest)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTNewDownloader interface {
	mock.TestingT
	Cleanup(func())
}

// NewDownloader creates a new instance of Downloader. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewDownloader(t mockConstructorTestingTNewDownloader) *Downloader {
	mock := &Downloader{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
