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
// 	protoc-gen-go v1.28.1
// 	protoc        (unknown)
// source: controlplane/v1/robot_accounts.proto

package v1

import (
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type RobotAccountServiceCreateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name       string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	WorkflowId string `protobuf:"bytes,2,opt,name=workflow_id,json=workflowId,proto3" json:"workflow_id,omitempty"`
}

func (x *RobotAccountServiceCreateRequest) Reset() {
	*x = RobotAccountServiceCreateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_robot_accounts_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RobotAccountServiceCreateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RobotAccountServiceCreateRequest) ProtoMessage() {}

func (x *RobotAccountServiceCreateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_robot_accounts_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RobotAccountServiceCreateRequest.ProtoReflect.Descriptor instead.
func (*RobotAccountServiceCreateRequest) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_robot_accounts_proto_rawDescGZIP(), []int{0}
}

func (x *RobotAccountServiceCreateRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *RobotAccountServiceCreateRequest) GetWorkflowId() string {
	if x != nil {
		return x.WorkflowId
	}
	return ""
}

type RobotAccountServiceCreateResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Result *RobotAccountServiceCreateResponse_RobotAccountFull `protobuf:"bytes,1,opt,name=result,proto3" json:"result,omitempty"`
}

func (x *RobotAccountServiceCreateResponse) Reset() {
	*x = RobotAccountServiceCreateResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_robot_accounts_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RobotAccountServiceCreateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RobotAccountServiceCreateResponse) ProtoMessage() {}

func (x *RobotAccountServiceCreateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_robot_accounts_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RobotAccountServiceCreateResponse.ProtoReflect.Descriptor instead.
func (*RobotAccountServiceCreateResponse) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_robot_accounts_proto_rawDescGZIP(), []int{1}
}

func (x *RobotAccountServiceCreateResponse) GetResult() *RobotAccountServiceCreateResponse_RobotAccountFull {
	if x != nil {
		return x.Result
	}
	return nil
}

type RobotAccountServiceRevokeRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *RobotAccountServiceRevokeRequest) Reset() {
	*x = RobotAccountServiceRevokeRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_robot_accounts_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RobotAccountServiceRevokeRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RobotAccountServiceRevokeRequest) ProtoMessage() {}

func (x *RobotAccountServiceRevokeRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_robot_accounts_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RobotAccountServiceRevokeRequest.ProtoReflect.Descriptor instead.
func (*RobotAccountServiceRevokeRequest) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_robot_accounts_proto_rawDescGZIP(), []int{2}
}

func (x *RobotAccountServiceRevokeRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type RobotAccountServiceRevokeResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *RobotAccountServiceRevokeResponse) Reset() {
	*x = RobotAccountServiceRevokeResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_robot_accounts_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RobotAccountServiceRevokeResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RobotAccountServiceRevokeResponse) ProtoMessage() {}

func (x *RobotAccountServiceRevokeResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_robot_accounts_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RobotAccountServiceRevokeResponse.ProtoReflect.Descriptor instead.
func (*RobotAccountServiceRevokeResponse) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_robot_accounts_proto_rawDescGZIP(), []int{3}
}

type RobotAccountServiceListRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	WorkflowId     string `protobuf:"bytes,1,opt,name=workflow_id,json=workflowId,proto3" json:"workflow_id,omitempty"`
	IncludeRevoked bool   `protobuf:"varint,2,opt,name=include_revoked,json=includeRevoked,proto3" json:"include_revoked,omitempty"`
}

func (x *RobotAccountServiceListRequest) Reset() {
	*x = RobotAccountServiceListRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_robot_accounts_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RobotAccountServiceListRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RobotAccountServiceListRequest) ProtoMessage() {}

func (x *RobotAccountServiceListRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_robot_accounts_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RobotAccountServiceListRequest.ProtoReflect.Descriptor instead.
func (*RobotAccountServiceListRequest) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_robot_accounts_proto_rawDescGZIP(), []int{4}
}

func (x *RobotAccountServiceListRequest) GetWorkflowId() string {
	if x != nil {
		return x.WorkflowId
	}
	return ""
}

func (x *RobotAccountServiceListRequest) GetIncludeRevoked() bool {
	if x != nil {
		return x.IncludeRevoked
	}
	return false
}

type RobotAccountServiceListResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Result []*RobotAccountServiceListResponse_RobotAccountItem `protobuf:"bytes,1,rep,name=result,proto3" json:"result,omitempty"`
}

func (x *RobotAccountServiceListResponse) Reset() {
	*x = RobotAccountServiceListResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_robot_accounts_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RobotAccountServiceListResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RobotAccountServiceListResponse) ProtoMessage() {}

func (x *RobotAccountServiceListResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_robot_accounts_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RobotAccountServiceListResponse.ProtoReflect.Descriptor instead.
func (*RobotAccountServiceListResponse) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_robot_accounts_proto_rawDescGZIP(), []int{5}
}

func (x *RobotAccountServiceListResponse) GetResult() []*RobotAccountServiceListResponse_RobotAccountItem {
	if x != nil {
		return x.Result
	}
	return nil
}

type RobotAccountServiceCreateResponse_RobotAccountFull struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id         string                 `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name       string                 `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	WorkflowId string                 `protobuf:"bytes,3,opt,name=workflow_id,json=workflowId,proto3" json:"workflow_id,omitempty"`
	CreatedAt  *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	RevokedAt  *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=revoked_at,json=revokedAt,proto3" json:"revoked_at,omitempty"`
	// The key is returned only during creation
	Key string `protobuf:"bytes,6,opt,name=key,proto3" json:"key,omitempty"`
}

func (x *RobotAccountServiceCreateResponse_RobotAccountFull) Reset() {
	*x = RobotAccountServiceCreateResponse_RobotAccountFull{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_robot_accounts_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RobotAccountServiceCreateResponse_RobotAccountFull) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RobotAccountServiceCreateResponse_RobotAccountFull) ProtoMessage() {}

func (x *RobotAccountServiceCreateResponse_RobotAccountFull) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_robot_accounts_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RobotAccountServiceCreateResponse_RobotAccountFull.ProtoReflect.Descriptor instead.
func (*RobotAccountServiceCreateResponse_RobotAccountFull) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_robot_accounts_proto_rawDescGZIP(), []int{1, 0}
}

func (x *RobotAccountServiceCreateResponse_RobotAccountFull) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *RobotAccountServiceCreateResponse_RobotAccountFull) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *RobotAccountServiceCreateResponse_RobotAccountFull) GetWorkflowId() string {
	if x != nil {
		return x.WorkflowId
	}
	return ""
}

func (x *RobotAccountServiceCreateResponse_RobotAccountFull) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *RobotAccountServiceCreateResponse_RobotAccountFull) GetRevokedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.RevokedAt
	}
	return nil
}

func (x *RobotAccountServiceCreateResponse_RobotAccountFull) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

type RobotAccountServiceListResponse_RobotAccountItem struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id         string                 `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name       string                 `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	WorkflowId string                 `protobuf:"bytes,3,opt,name=workflow_id,json=workflowId,proto3" json:"workflow_id,omitempty"`
	CreatedAt  *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	RevokedAt  *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=revoked_at,json=revokedAt,proto3" json:"revoked_at,omitempty"`
}

func (x *RobotAccountServiceListResponse_RobotAccountItem) Reset() {
	*x = RobotAccountServiceListResponse_RobotAccountItem{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_robot_accounts_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RobotAccountServiceListResponse_RobotAccountItem) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RobotAccountServiceListResponse_RobotAccountItem) ProtoMessage() {}

func (x *RobotAccountServiceListResponse_RobotAccountItem) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_robot_accounts_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RobotAccountServiceListResponse_RobotAccountItem.ProtoReflect.Descriptor instead.
func (*RobotAccountServiceListResponse_RobotAccountItem) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_robot_accounts_proto_rawDescGZIP(), []int{5, 0}
}

func (x *RobotAccountServiceListResponse_RobotAccountItem) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *RobotAccountServiceListResponse_RobotAccountItem) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *RobotAccountServiceListResponse_RobotAccountItem) GetWorkflowId() string {
	if x != nil {
		return x.WorkflowId
	}
	return ""
}

func (x *RobotAccountServiceListResponse_RobotAccountItem) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *RobotAccountServiceListResponse_RobotAccountItem) GetRevokedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.RevokedAt
	}
	return nil
}

var File_controlplane_v1_robot_accounts_proto protoreflect.FileDescriptor

var file_controlplane_v1_robot_accounts_proto_rawDesc = []byte{
	0x0a, 0x24, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x76,
	0x31, 0x2f, 0x72, 0x6f, 0x62, 0x6f, 0x74, 0x5f, 0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70,
	0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74,
	0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0x61, 0x0a, 0x20, 0x52, 0x6f, 0x62, 0x6f, 0x74, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e,
	0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x29, 0x0a, 0x0b, 0x77, 0x6f, 0x72,
	0x6b, 0x66, 0x6c, 0x6f, 0x77, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x08,
	0xfa, 0x42, 0x05, 0x72, 0x03, 0xb0, 0x01, 0x01, 0x52, 0x0a, 0x77, 0x6f, 0x72, 0x6b, 0x66, 0x6c,
	0x6f, 0x77, 0x49, 0x64, 0x22, 0xe2, 0x02, 0x0a, 0x21, 0x52, 0x6f, 0x62, 0x6f, 0x74, 0x41, 0x63,
	0x63, 0x6f, 0x75, 0x6e, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x43, 0x72, 0x65, 0x61,
	0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x5b, 0x0a, 0x06, 0x72, 0x65,
	0x73, 0x75, 0x6c, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x43, 0x2e, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x6f, 0x62,
	0x6f, 0x74, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x52,
	0x6f, 0x62, 0x6f, 0x74, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x46, 0x75, 0x6c, 0x6c, 0x52,
	0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x1a, 0xdf, 0x01, 0x0a, 0x10, 0x52, 0x6f, 0x62, 0x6f,
	0x74, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x46, 0x75, 0x6c, 0x6c, 0x12, 0x0e, 0x0a, 0x02,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65,
	0x12, 0x1f, 0x0a, 0x0b, 0x77, 0x6f, 0x72, 0x6b, 0x66, 0x6c, 0x6f, 0x77, 0x5f, 0x69, 0x64, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x77, 0x6f, 0x72, 0x6b, 0x66, 0x6c, 0x6f, 0x77, 0x49,
	0x64, 0x12, 0x39, 0x0a, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x52, 0x09, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x39, 0x0a, 0x0a,
	0x72, 0x65, 0x76, 0x6f, 0x6b, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x72, 0x65,
	0x76, 0x6f, 0x6b, 0x65, 0x64, 0x41, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x06,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x22, 0x3c, 0x0a, 0x20, 0x52, 0x6f, 0x62,
	0x6f, 0x74, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x52, 0x65, 0x76, 0x6f, 0x6b, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x18, 0x0a,
	0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x72, 0x03,
	0xb0, 0x01, 0x01, 0x52, 0x02, 0x69, 0x64, 0x22, 0x23, 0x0a, 0x21, 0x52, 0x6f, 0x62, 0x6f, 0x74,
	0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65,
	0x76, 0x6f, 0x6b, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x74, 0x0a, 0x1e,
	0x52, 0x6f, 0x62, 0x6f, 0x74, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x53, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x29,
	0x0a, 0x0b, 0x77, 0x6f, 0x72, 0x6b, 0x66, 0x6c, 0x6f, 0x77, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x72, 0x03, 0xb0, 0x01, 0x01, 0x52, 0x0a, 0x77,
	0x6f, 0x72, 0x6b, 0x66, 0x6c, 0x6f, 0x77, 0x49, 0x64, 0x12, 0x27, 0x0a, 0x0f, 0x69, 0x6e, 0x63,
	0x6c, 0x75, 0x64, 0x65, 0x5f, 0x72, 0x65, 0x76, 0x6f, 0x6b, 0x65, 0x64, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x0e, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x52, 0x65, 0x76, 0x6f, 0x6b,
	0x65, 0x64, 0x22, 0xcc, 0x02, 0x0a, 0x1f, 0x52, 0x6f, 0x62, 0x6f, 0x74, 0x41, 0x63, 0x63, 0x6f,
	0x75, 0x6e, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x59, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74,
	0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x41, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x6f, 0x62, 0x6f, 0x74, 0x41, 0x63,
	0x63, 0x6f, 0x75, 0x6e, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x4c, 0x69, 0x73, 0x74,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x52, 0x6f, 0x62, 0x6f, 0x74, 0x41, 0x63,
	0x63, 0x6f, 0x75, 0x6e, 0x74, 0x49, 0x74, 0x65, 0x6d, 0x52, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c,
	0x74, 0x1a, 0xcd, 0x01, 0x0a, 0x10, 0x52, 0x6f, 0x62, 0x6f, 0x74, 0x41, 0x63, 0x63, 0x6f, 0x75,
	0x6e, 0x74, 0x49, 0x74, 0x65, 0x6d, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1f, 0x0a, 0x0b, 0x77, 0x6f,
	0x72, 0x6b, 0x66, 0x6c, 0x6f, 0x77, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0a, 0x77, 0x6f, 0x72, 0x6b, 0x66, 0x6c, 0x6f, 0x77, 0x49, 0x64, 0x12, 0x39, 0x0a, 0x0a, 0x63,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x63, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x39, 0x0a, 0x0a, 0x72, 0x65, 0x76, 0x6f, 0x6b, 0x65,
	0x64, 0x5f, 0x61, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x72, 0x65, 0x76, 0x6f, 0x6b, 0x65, 0x64, 0x41,
	0x74, 0x32, 0xe2, 0x02, 0x0a, 0x13, 0x52, 0x6f, 0x62, 0x6f, 0x74, 0x41, 0x63, 0x63, 0x6f, 0x75,
	0x6e, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x6f, 0x0a, 0x06, 0x43, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x12, 0x31, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61,
	0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x6f, 0x62, 0x6f, 0x74, 0x41, 0x63, 0x63, 0x6f, 0x75,
	0x6e, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x32, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x6f, 0x62, 0x6f, 0x74, 0x41, 0x63,
	0x63, 0x6f, 0x75, 0x6e, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x43, 0x72, 0x65, 0x61,
	0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x69, 0x0a, 0x04, 0x4c, 0x69,
	0x73, 0x74, 0x12, 0x2f, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e,
	0x65, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x6f, 0x62, 0x6f, 0x74, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e,
	0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x30, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61,
	0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x6f, 0x62, 0x6f, 0x74, 0x41, 0x63, 0x63, 0x6f, 0x75,
	0x6e, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x6f, 0x0a, 0x06, 0x52, 0x65, 0x76, 0x6f, 0x6b, 0x65, 0x12,
	0x31, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76,
	0x31, 0x2e, 0x52, 0x6f, 0x62, 0x6f, 0x74, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x76, 0x6f, 0x6b, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x32, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e,
	0x65, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x6f, 0x62, 0x6f, 0x74, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e,
	0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x76, 0x6f, 0x6b, 0x65, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x4a, 0x5a, 0x48, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x6c, 0x6f, 0x6f, 0x70, 0x2d, 0x64,
	0x65, 0x76, 0x2f, 0x62, 0x65, 0x64, 0x72, 0x6f, 0x63, 0x6b, 0x2f, 0x61, 0x70, 0x70, 0x2f, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x76, 0x31, 0x3b,
	0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controlplane_v1_robot_accounts_proto_rawDescOnce sync.Once
	file_controlplane_v1_robot_accounts_proto_rawDescData = file_controlplane_v1_robot_accounts_proto_rawDesc
)

func file_controlplane_v1_robot_accounts_proto_rawDescGZIP() []byte {
	file_controlplane_v1_robot_accounts_proto_rawDescOnce.Do(func() {
		file_controlplane_v1_robot_accounts_proto_rawDescData = protoimpl.X.CompressGZIP(file_controlplane_v1_robot_accounts_proto_rawDescData)
	})
	return file_controlplane_v1_robot_accounts_proto_rawDescData
}

var file_controlplane_v1_robot_accounts_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_controlplane_v1_robot_accounts_proto_goTypes = []interface{}{
	(*RobotAccountServiceCreateRequest)(nil),                   // 0: controlplane.v1.RobotAccountServiceCreateRequest
	(*RobotAccountServiceCreateResponse)(nil),                  // 1: controlplane.v1.RobotAccountServiceCreateResponse
	(*RobotAccountServiceRevokeRequest)(nil),                   // 2: controlplane.v1.RobotAccountServiceRevokeRequest
	(*RobotAccountServiceRevokeResponse)(nil),                  // 3: controlplane.v1.RobotAccountServiceRevokeResponse
	(*RobotAccountServiceListRequest)(nil),                     // 4: controlplane.v1.RobotAccountServiceListRequest
	(*RobotAccountServiceListResponse)(nil),                    // 5: controlplane.v1.RobotAccountServiceListResponse
	(*RobotAccountServiceCreateResponse_RobotAccountFull)(nil), // 6: controlplane.v1.RobotAccountServiceCreateResponse.RobotAccountFull
	(*RobotAccountServiceListResponse_RobotAccountItem)(nil),   // 7: controlplane.v1.RobotAccountServiceListResponse.RobotAccountItem
	(*timestamppb.Timestamp)(nil),                              // 8: google.protobuf.Timestamp
}
var file_controlplane_v1_robot_accounts_proto_depIdxs = []int32{
	6, // 0: controlplane.v1.RobotAccountServiceCreateResponse.result:type_name -> controlplane.v1.RobotAccountServiceCreateResponse.RobotAccountFull
	7, // 1: controlplane.v1.RobotAccountServiceListResponse.result:type_name -> controlplane.v1.RobotAccountServiceListResponse.RobotAccountItem
	8, // 2: controlplane.v1.RobotAccountServiceCreateResponse.RobotAccountFull.created_at:type_name -> google.protobuf.Timestamp
	8, // 3: controlplane.v1.RobotAccountServiceCreateResponse.RobotAccountFull.revoked_at:type_name -> google.protobuf.Timestamp
	8, // 4: controlplane.v1.RobotAccountServiceListResponse.RobotAccountItem.created_at:type_name -> google.protobuf.Timestamp
	8, // 5: controlplane.v1.RobotAccountServiceListResponse.RobotAccountItem.revoked_at:type_name -> google.protobuf.Timestamp
	0, // 6: controlplane.v1.RobotAccountService.Create:input_type -> controlplane.v1.RobotAccountServiceCreateRequest
	4, // 7: controlplane.v1.RobotAccountService.List:input_type -> controlplane.v1.RobotAccountServiceListRequest
	2, // 8: controlplane.v1.RobotAccountService.Revoke:input_type -> controlplane.v1.RobotAccountServiceRevokeRequest
	1, // 9: controlplane.v1.RobotAccountService.Create:output_type -> controlplane.v1.RobotAccountServiceCreateResponse
	5, // 10: controlplane.v1.RobotAccountService.List:output_type -> controlplane.v1.RobotAccountServiceListResponse
	3, // 11: controlplane.v1.RobotAccountService.Revoke:output_type -> controlplane.v1.RobotAccountServiceRevokeResponse
	9, // [9:12] is the sub-list for method output_type
	6, // [6:9] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_controlplane_v1_robot_accounts_proto_init() }
func file_controlplane_v1_robot_accounts_proto_init() {
	if File_controlplane_v1_robot_accounts_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controlplane_v1_robot_accounts_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RobotAccountServiceCreateRequest); i {
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
		file_controlplane_v1_robot_accounts_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RobotAccountServiceCreateResponse); i {
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
		file_controlplane_v1_robot_accounts_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RobotAccountServiceRevokeRequest); i {
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
		file_controlplane_v1_robot_accounts_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RobotAccountServiceRevokeResponse); i {
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
		file_controlplane_v1_robot_accounts_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RobotAccountServiceListRequest); i {
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
		file_controlplane_v1_robot_accounts_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RobotAccountServiceListResponse); i {
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
		file_controlplane_v1_robot_accounts_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RobotAccountServiceCreateResponse_RobotAccountFull); i {
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
		file_controlplane_v1_robot_accounts_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RobotAccountServiceListResponse_RobotAccountItem); i {
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
			RawDescriptor: file_controlplane_v1_robot_accounts_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_controlplane_v1_robot_accounts_proto_goTypes,
		DependencyIndexes: file_controlplane_v1_robot_accounts_proto_depIdxs,
		MessageInfos:      file_controlplane_v1_robot_accounts_proto_msgTypes,
	}.Build()
	File_controlplane_v1_robot_accounts_proto = out.File
	file_controlplane_v1_robot_accounts_proto_rawDesc = nil
	file_controlplane_v1_robot_accounts_proto_goTypes = nil
	file_controlplane_v1_robot_accounts_proto_depIdxs = nil
}
