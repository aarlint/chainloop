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

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        (unknown)
// source: controlplane/v1/cas_backends.proto

package v1

import (
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	structpb "google.golang.org/protobuf/types/known/structpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type CASBackendServiceListRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *CASBackendServiceListRequest) Reset() {
	*x = CASBackendServiceListRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_cas_backends_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CASBackendServiceListRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CASBackendServiceListRequest) ProtoMessage() {}

func (x *CASBackendServiceListRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_cas_backends_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CASBackendServiceListRequest.ProtoReflect.Descriptor instead.
func (*CASBackendServiceListRequest) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_cas_backends_proto_rawDescGZIP(), []int{0}
}

type CASBackendServiceListResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Result []*CASBackendItem `protobuf:"bytes,1,rep,name=result,proto3" json:"result,omitempty"`
}

func (x *CASBackendServiceListResponse) Reset() {
	*x = CASBackendServiceListResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_cas_backends_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CASBackendServiceListResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CASBackendServiceListResponse) ProtoMessage() {}

func (x *CASBackendServiceListResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_cas_backends_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CASBackendServiceListResponse.ProtoReflect.Descriptor instead.
func (*CASBackendServiceListResponse) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_cas_backends_proto_rawDescGZIP(), []int{1}
}

func (x *CASBackendServiceListResponse) GetResult() []*CASBackendItem {
	if x != nil {
		return x.Result
	}
	return nil
}

type CASBackendServiceCreateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Location, e.g. bucket name, OCI bucket name, ...
	Location string `protobuf:"bytes,1,opt,name=location,proto3" json:"location,omitempty"`
	// Type of the backend, OCI, S3, ...
	Provider string `protobuf:"bytes,2,opt,name=provider,proto3" json:"provider,omitempty"`
	// Descriptive name
	Description string `protobuf:"bytes,3,opt,name=description,proto3" json:"description,omitempty"`
	// Set as default in your organization
	Default bool `protobuf:"varint,4,opt,name=default,proto3" json:"default,omitempty"`
	// Arbitrary configuration for the integration
	Credentials *structpb.Struct `protobuf:"bytes,5,opt,name=credentials,proto3" json:"credentials,omitempty"`
}

func (x *CASBackendServiceCreateRequest) Reset() {
	*x = CASBackendServiceCreateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_cas_backends_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CASBackendServiceCreateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CASBackendServiceCreateRequest) ProtoMessage() {}

func (x *CASBackendServiceCreateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_cas_backends_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CASBackendServiceCreateRequest.ProtoReflect.Descriptor instead.
func (*CASBackendServiceCreateRequest) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_cas_backends_proto_rawDescGZIP(), []int{2}
}

func (x *CASBackendServiceCreateRequest) GetLocation() string {
	if x != nil {
		return x.Location
	}
	return ""
}

func (x *CASBackendServiceCreateRequest) GetProvider() string {
	if x != nil {
		return x.Provider
	}
	return ""
}

func (x *CASBackendServiceCreateRequest) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *CASBackendServiceCreateRequest) GetDefault() bool {
	if x != nil {
		return x.Default
	}
	return false
}

func (x *CASBackendServiceCreateRequest) GetCredentials() *structpb.Struct {
	if x != nil {
		return x.Credentials
	}
	return nil
}

type CASBackendServiceCreateResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Result *CASBackendItem `protobuf:"bytes,1,opt,name=result,proto3" json:"result,omitempty"`
}

func (x *CASBackendServiceCreateResponse) Reset() {
	*x = CASBackendServiceCreateResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_cas_backends_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CASBackendServiceCreateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CASBackendServiceCreateResponse) ProtoMessage() {}

func (x *CASBackendServiceCreateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_cas_backends_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CASBackendServiceCreateResponse.ProtoReflect.Descriptor instead.
func (*CASBackendServiceCreateResponse) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_cas_backends_proto_rawDescGZIP(), []int{3}
}

func (x *CASBackendServiceCreateResponse) GetResult() *CASBackendItem {
	if x != nil {
		return x.Result
	}
	return nil
}

// Update a CAS backend is limited to
// - description
// - set is as default
// - rotate credentials
type CASBackendServiceUpdateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// UUID of the workflow to attach
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// Descriptive name
	Description string `protobuf:"bytes,2,opt,name=description,proto3" json:"description,omitempty"`
	// Set as default in your organization
	Default bool `protobuf:"varint,3,opt,name=default,proto3" json:"default,omitempty"`
	// Credentials, useful for rotation
	Credentials *structpb.Struct `protobuf:"bytes,4,opt,name=credentials,proto3" json:"credentials,omitempty"`
}

func (x *CASBackendServiceUpdateRequest) Reset() {
	*x = CASBackendServiceUpdateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_cas_backends_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CASBackendServiceUpdateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CASBackendServiceUpdateRequest) ProtoMessage() {}

func (x *CASBackendServiceUpdateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_cas_backends_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CASBackendServiceUpdateRequest.ProtoReflect.Descriptor instead.
func (*CASBackendServiceUpdateRequest) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_cas_backends_proto_rawDescGZIP(), []int{4}
}

func (x *CASBackendServiceUpdateRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *CASBackendServiceUpdateRequest) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *CASBackendServiceUpdateRequest) GetDefault() bool {
	if x != nil {
		return x.Default
	}
	return false
}

func (x *CASBackendServiceUpdateRequest) GetCredentials() *structpb.Struct {
	if x != nil {
		return x.Credentials
	}
	return nil
}

type CASBackendServiceUpdateResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Result *CASBackendItem `protobuf:"bytes,1,opt,name=result,proto3" json:"result,omitempty"`
}

func (x *CASBackendServiceUpdateResponse) Reset() {
	*x = CASBackendServiceUpdateResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_cas_backends_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CASBackendServiceUpdateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CASBackendServiceUpdateResponse) ProtoMessage() {}

func (x *CASBackendServiceUpdateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_cas_backends_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CASBackendServiceUpdateResponse.ProtoReflect.Descriptor instead.
func (*CASBackendServiceUpdateResponse) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_cas_backends_proto_rawDescGZIP(), []int{5}
}

func (x *CASBackendServiceUpdateResponse) GetResult() *CASBackendItem {
	if x != nil {
		return x.Result
	}
	return nil
}

var File_controlplane_v1_cas_backends_proto protoreflect.FileDescriptor

var file_controlplane_v1_cas_backends_proto_rawDesc = []byte{
	0x0a, 0x22, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x76,
	0x31, 0x2f, 0x63, 0x61, 0x73, 0x5f, 0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x73, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61,
	0x6e, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x27, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c,
	0x61, 0x6e, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x5f,
	0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17,
	0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x1e, 0x0a, 0x1c, 0x43, 0x41, 0x53, 0x42, 0x61, 0x63, 0x6b,
	0x65, 0x6e, 0x64, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x58, 0x0a, 0x1d, 0x43, 0x41, 0x53, 0x42, 0x61, 0x63, 0x6b,
	0x65, 0x6e, 0x64, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x37, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74,
	0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x41, 0x53, 0x42, 0x61, 0x63, 0x6b,
	0x65, 0x6e, 0x64, 0x49, 0x74, 0x65, 0x6d, 0x52, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x22,
	0xeb, 0x01, 0x0a, 0x1e, 0x43, 0x41, 0x53, 0x42, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x23, 0x0a, 0x08, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x72, 0x02, 0x10, 0x01, 0x52, 0x08, 0x6c,
	0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x23, 0x0a, 0x08, 0x70, 0x72, 0x6f, 0x76, 0x69,
	0x64, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x72, 0x02,
	0x10, 0x01, 0x52, 0x08, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x12, 0x20, 0x0a, 0x0b,
	0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x18,
	0x0a, 0x07, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x07, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x12, 0x43, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x8a, 0x01, 0x02, 0x10, 0x01,
	0x52, 0x0b, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x22, 0x5a, 0x0a,
	0x1f, 0x43, 0x41, 0x53, 0x42, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x53, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x37, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1f, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e,
	0x76, 0x31, 0x2e, 0x43, 0x41, 0x53, 0x42, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x49, 0x74, 0x65,
	0x6d, 0x52, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0xb1, 0x01, 0x0a, 0x1e, 0x43, 0x41,
	0x53, 0x42, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x55,
	0x70, 0x64, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x02,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x72, 0x03, 0xb0,
	0x01, 0x01, 0x52, 0x02, 0x69, 0x64, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73,
	0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x18, 0x0a, 0x07, 0x64, 0x65, 0x66, 0x61,
	0x75, 0x6c, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x64, 0x65, 0x66, 0x61, 0x75,
	0x6c, 0x74, 0x12, 0x39, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c,
	0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74,
	0x52, 0x0b, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x22, 0x5a, 0x0a,
	0x1f, 0x43, 0x41, 0x53, 0x42, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x53, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x37, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1f, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e,
	0x76, 0x31, 0x2e, 0x43, 0x41, 0x53, 0x42, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x49, 0x74, 0x65,
	0x6d, 0x52, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x32, 0xd4, 0x02, 0x0a, 0x11, 0x43, 0x41,
	0x53, 0x42, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12,
	0x65, 0x0a, 0x04, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x2d, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x41, 0x53, 0x42, 0x61, 0x63,
	0x6b, 0x65, 0x6e, 0x64, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2e, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x41, 0x53, 0x42, 0x61, 0x63, 0x6b,
	0x65, 0x6e, 0x64, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x6b, 0x0a, 0x06, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65,
	0x12, 0x2f, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e,
	0x76, 0x31, 0x2e, 0x43, 0x41, 0x53, 0x42, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x53, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x30, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65,
	0x2e, 0x76, 0x31, 0x2e, 0x43, 0x41, 0x53, 0x42, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x6b, 0x0a, 0x06, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x12, 0x2f, 0x2e,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e,
	0x43, 0x41, 0x53, 0x42, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x30,
	0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31,
	0x2e, 0x43, 0x41, 0x53, 0x42, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x53, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x42, 0x4c, 0x5a, 0x4a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63,
	0x68, 0x61, 0x69, 0x6e, 0x6c, 0x6f, 0x6f, 0x70, 0x2d, 0x64, 0x65, 0x76, 0x2f, 0x63, 0x68, 0x61,
	0x69, 0x6e, 0x6c, 0x6f, 0x6f, 0x70, 0x2f, 0x61, 0x70, 0x70, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72,
	0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x76, 0x31, 0x3b, 0x76, 0x31, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controlplane_v1_cas_backends_proto_rawDescOnce sync.Once
	file_controlplane_v1_cas_backends_proto_rawDescData = file_controlplane_v1_cas_backends_proto_rawDesc
)

func file_controlplane_v1_cas_backends_proto_rawDescGZIP() []byte {
	file_controlplane_v1_cas_backends_proto_rawDescOnce.Do(func() {
		file_controlplane_v1_cas_backends_proto_rawDescData = protoimpl.X.CompressGZIP(file_controlplane_v1_cas_backends_proto_rawDescData)
	})
	return file_controlplane_v1_cas_backends_proto_rawDescData
}

var file_controlplane_v1_cas_backends_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_controlplane_v1_cas_backends_proto_goTypes = []interface{}{
	(*CASBackendServiceListRequest)(nil),    // 0: controlplane.v1.CASBackendServiceListRequest
	(*CASBackendServiceListResponse)(nil),   // 1: controlplane.v1.CASBackendServiceListResponse
	(*CASBackendServiceCreateRequest)(nil),  // 2: controlplane.v1.CASBackendServiceCreateRequest
	(*CASBackendServiceCreateResponse)(nil), // 3: controlplane.v1.CASBackendServiceCreateResponse
	(*CASBackendServiceUpdateRequest)(nil),  // 4: controlplane.v1.CASBackendServiceUpdateRequest
	(*CASBackendServiceUpdateResponse)(nil), // 5: controlplane.v1.CASBackendServiceUpdateResponse
	(*CASBackendItem)(nil),                  // 6: controlplane.v1.CASBackendItem
	(*structpb.Struct)(nil),                 // 7: google.protobuf.Struct
}
var file_controlplane_v1_cas_backends_proto_depIdxs = []int32{
	6, // 0: controlplane.v1.CASBackendServiceListResponse.result:type_name -> controlplane.v1.CASBackendItem
	7, // 1: controlplane.v1.CASBackendServiceCreateRequest.credentials:type_name -> google.protobuf.Struct
	6, // 2: controlplane.v1.CASBackendServiceCreateResponse.result:type_name -> controlplane.v1.CASBackendItem
	7, // 3: controlplane.v1.CASBackendServiceUpdateRequest.credentials:type_name -> google.protobuf.Struct
	6, // 4: controlplane.v1.CASBackendServiceUpdateResponse.result:type_name -> controlplane.v1.CASBackendItem
	0, // 5: controlplane.v1.CASBackendService.List:input_type -> controlplane.v1.CASBackendServiceListRequest
	2, // 6: controlplane.v1.CASBackendService.Create:input_type -> controlplane.v1.CASBackendServiceCreateRequest
	4, // 7: controlplane.v1.CASBackendService.Update:input_type -> controlplane.v1.CASBackendServiceUpdateRequest
	1, // 8: controlplane.v1.CASBackendService.List:output_type -> controlplane.v1.CASBackendServiceListResponse
	3, // 9: controlplane.v1.CASBackendService.Create:output_type -> controlplane.v1.CASBackendServiceCreateResponse
	5, // 10: controlplane.v1.CASBackendService.Update:output_type -> controlplane.v1.CASBackendServiceUpdateResponse
	8, // [8:11] is the sub-list for method output_type
	5, // [5:8] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_controlplane_v1_cas_backends_proto_init() }
func file_controlplane_v1_cas_backends_proto_init() {
	if File_controlplane_v1_cas_backends_proto != nil {
		return
	}
	file_controlplane_v1_response_messages_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_controlplane_v1_cas_backends_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CASBackendServiceListRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controlplane_v1_cas_backends_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CASBackendServiceListResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controlplane_v1_cas_backends_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CASBackendServiceCreateRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controlplane_v1_cas_backends_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CASBackendServiceCreateResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controlplane_v1_cas_backends_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CASBackendServiceUpdateRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controlplane_v1_cas_backends_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CASBackendServiceUpdateResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_controlplane_v1_cas_backends_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_controlplane_v1_cas_backends_proto_goTypes,
		DependencyIndexes: file_controlplane_v1_cas_backends_proto_depIdxs,
		MessageInfos:      file_controlplane_v1_cas_backends_proto_msgTypes,
	}.Build()
	File_controlplane_v1_cas_backends_proto = out.File
	file_controlplane_v1_cas_backends_proto_rawDesc = nil
	file_controlplane_v1_cas_backends_proto_goTypes = nil
	file_controlplane_v1_cas_backends_proto_depIdxs = nil
}
