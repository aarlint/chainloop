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
// source: controlplane/v1/status.proto

package v1

import (
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type InfozRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *InfozRequest) Reset() {
	*x = InfozRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_status_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *InfozRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InfozRequest) ProtoMessage() {}

func (x *InfozRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_status_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InfozRequest.ProtoReflect.Descriptor instead.
func (*InfozRequest) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_status_proto_rawDescGZIP(), []int{0}
}

type StatuszRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Parameter that can be used by readiness probes
	// The main difference is that readiness probes will take into account that all
	// dependent services are up and ready
	Readiness bool `protobuf:"varint,1,opt,name=readiness,proto3" json:"readiness,omitempty"`
}

func (x *StatuszRequest) Reset() {
	*x = StatuszRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_status_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StatuszRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StatuszRequest) ProtoMessage() {}

func (x *StatuszRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_status_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StatuszRequest.ProtoReflect.Descriptor instead.
func (*StatuszRequest) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_status_proto_rawDescGZIP(), []int{1}
}

func (x *StatuszRequest) GetReadiness() bool {
	if x != nil {
		return x.Readiness
	}
	return false
}

type InfozResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	LoginUrl string `protobuf:"bytes,1,opt,name=login_url,json=loginURL,proto3" json:"login_url,omitempty"`
	Version  string `protobuf:"bytes,2,opt,name=version,proto3" json:"version,omitempty"`
}

func (x *InfozResponse) Reset() {
	*x = InfozResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_status_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *InfozResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InfozResponse) ProtoMessage() {}

func (x *InfozResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_status_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InfozResponse.ProtoReflect.Descriptor instead.
func (*InfozResponse) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_status_proto_rawDescGZIP(), []int{2}
}

func (x *InfozResponse) GetLoginUrl() string {
	if x != nil {
		return x.LoginUrl
	}
	return ""
}

func (x *InfozResponse) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

type StatuszResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *StatuszResponse) Reset() {
	*x = StatuszResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controlplane_v1_status_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StatuszResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StatuszResponse) ProtoMessage() {}

func (x *StatuszResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controlplane_v1_status_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StatuszResponse.ProtoReflect.Descriptor instead.
func (*StatuszResponse) Descriptor() ([]byte, []int) {
	return file_controlplane_v1_status_proto_rawDescGZIP(), []int{3}
}

var File_controlplane_v1_status_proto protoreflect.FileDescriptor

var file_controlplane_v1_status_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x76,
	0x31, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0f,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x1a,
	0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f,
	0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x0e, 0x0a,
	0x0c, 0x49, 0x6e, 0x66, 0x6f, 0x7a, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x2e, 0x0a,
	0x0e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x7a, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x1c, 0x0a, 0x09, 0x72, 0x65, 0x61, 0x64, 0x69, 0x6e, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x09, 0x72, 0x65, 0x61, 0x64, 0x69, 0x6e, 0x65, 0x73, 0x73, 0x22, 0x46, 0x0a,
	0x0d, 0x49, 0x6e, 0x66, 0x6f, 0x7a, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1b,
	0x0a, 0x09, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x5f, 0x75, 0x72, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x08, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x55, 0x52, 0x4c, 0x12, 0x18, 0x0a, 0x07, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x76, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x11, 0x0a, 0x0f, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x7a,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x32, 0xc7, 0x01, 0x0a, 0x0d, 0x53, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x56, 0x0a, 0x05, 0x49, 0x6e,
	0x66, 0x6f, 0x7a, 0x12, 0x1d, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61,
	0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x49, 0x6e, 0x66, 0x6f, 0x7a, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x1e, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e,
	0x65, 0x2e, 0x76, 0x31, 0x2e, 0x49, 0x6e, 0x66, 0x6f, 0x7a, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x22, 0x0e, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x08, 0x12, 0x06, 0x2f, 0x69, 0x6e, 0x66,
	0x6f, 0x7a, 0x12, 0x5e, 0x0a, 0x07, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x7a, 0x12, 0x1f, 0x2e,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31, 0x2e,
	0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x7a, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x20,
	0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2e, 0x76, 0x31,
	0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x7a, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x22, 0x10, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x0a, 0x12, 0x08, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x7a, 0x42, 0x4a, 0x5a, 0x48, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x6c, 0x6f, 0x6f, 0x70, 0x2d, 0x64, 0x65, 0x76, 0x2f, 0x62,
	0x65, 0x64, 0x72, 0x6f, 0x63, 0x6b, 0x2f, 0x61, 0x70, 0x70, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72,
	0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x76, 0x31, 0x3b, 0x76, 0x31, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controlplane_v1_status_proto_rawDescOnce sync.Once
	file_controlplane_v1_status_proto_rawDescData = file_controlplane_v1_status_proto_rawDesc
)

func file_controlplane_v1_status_proto_rawDescGZIP() []byte {
	file_controlplane_v1_status_proto_rawDescOnce.Do(func() {
		file_controlplane_v1_status_proto_rawDescData = protoimpl.X.CompressGZIP(file_controlplane_v1_status_proto_rawDescData)
	})
	return file_controlplane_v1_status_proto_rawDescData
}

var file_controlplane_v1_status_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_controlplane_v1_status_proto_goTypes = []interface{}{
	(*InfozRequest)(nil),    // 0: controlplane.v1.InfozRequest
	(*StatuszRequest)(nil),  // 1: controlplane.v1.StatuszRequest
	(*InfozResponse)(nil),   // 2: controlplane.v1.InfozResponse
	(*StatuszResponse)(nil), // 3: controlplane.v1.StatuszResponse
}
var file_controlplane_v1_status_proto_depIdxs = []int32{
	0, // 0: controlplane.v1.StatusService.Infoz:input_type -> controlplane.v1.InfozRequest
	1, // 1: controlplane.v1.StatusService.Statusz:input_type -> controlplane.v1.StatuszRequest
	2, // 2: controlplane.v1.StatusService.Infoz:output_type -> controlplane.v1.InfozResponse
	3, // 3: controlplane.v1.StatusService.Statusz:output_type -> controlplane.v1.StatuszResponse
	2, // [2:4] is the sub-list for method output_type
	0, // [0:2] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_controlplane_v1_status_proto_init() }
func file_controlplane_v1_status_proto_init() {
	if File_controlplane_v1_status_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controlplane_v1_status_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*InfozRequest); i {
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
		file_controlplane_v1_status_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StatuszRequest); i {
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
		file_controlplane_v1_status_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*InfozResponse); i {
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
		file_controlplane_v1_status_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StatuszResponse); i {
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
			RawDescriptor: file_controlplane_v1_status_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_controlplane_v1_status_proto_goTypes,
		DependencyIndexes: file_controlplane_v1_status_proto_depIdxs,
		MessageInfos:      file_controlplane_v1_status_proto_msgTypes,
	}.Build()
	File_controlplane_v1_status_proto = out.File
	file_controlplane_v1_status_proto_rawDesc = nil
	file_controlplane_v1_status_proto_goTypes = nil
	file_controlplane_v1_status_proto_depIdxs = nil
}
