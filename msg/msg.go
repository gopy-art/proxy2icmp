package msg

import (
	fmt "fmt"
	math "math"
	proto "github.com/golang/protobuf/proto"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type MyMsg_TYPE int32

const (
	MyMsg_DATA  MyMsg_TYPE = 0
	MyMsg_PING  MyMsg_TYPE = 1
	MyMsg_KICK  MyMsg_TYPE = 2
	MyMsg_MAGIC MyMsg_TYPE = 57005
)

var MyMsg_TYPE_name = map[int32]string{
	0:     "DATA",
	1:     "PING",
	2:     "KICK",
	57005: "MAGIC",
}

var MyMsg_TYPE_value = map[string]int32{
	"DATA":  0,
	"PING":  1,
	"KICK":  2,
	"MAGIC": 57005,
}

func (x MyMsg_TYPE) String() string {
	return proto.EnumName(MyMsg_TYPE_name, int32(x))
}

func (MyMsg_TYPE) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_c06e4cca6c2cc899, []int{0, 0}
}

type MyMsg struct {
	Id                   string   `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Type                 int32    `protobuf:"varint,2,opt,name=type,proto3" json:"type,omitempty"`
	Target               string   `protobuf:"bytes,3,opt,name=target,proto3" json:"target,omitempty"`
	Data                 []byte   `protobuf:"bytes,4,opt,name=data,proto3" json:"data,omitempty"`
	Rproto               int32    `protobuf:"zigzag32,5,opt,name=rproto,proto3" json:"rproto,omitempty"`
	Magic                int32    `protobuf:"zigzag32,6,opt,name=magic,proto3" json:"magic,omitempty"`
	Key                  int32    `protobuf:"zigzag32,7,opt,name=key,proto3" json:"key,omitempty"`
	Timeout              int32    `protobuf:"varint,8,opt,name=timeout,proto3" json:"timeout,omitempty"`
	Tcpmode              int32    `protobuf:"varint,9,opt,name=tcpmode,proto3" json:"tcpmode,omitempty"`
	TcpmodeBuffersize    int32    `protobuf:"varint,10,opt,name=tcpmode_buffersize,json=tcpmodeBuffersize,proto3" json:"tcpmode_buffersize,omitempty"`
	TcpmodeMaxwin        int32    `protobuf:"varint,11,opt,name=tcpmode_maxwin,json=tcpmodeMaxwin,proto3" json:"tcpmode_maxwin,omitempty"`
	TcpmodeResendTimems  int32    `protobuf:"varint,12,opt,name=tcpmode_resend_timems,json=tcpmodeResendTimems,proto3" json:"tcpmode_resend_timems,omitempty"`
	TcpmodeCompress      int32    `protobuf:"varint,13,opt,name=tcpmode_compress,json=tcpmodeCompress,proto3" json:"tcpmode_compress,omitempty"`
	TcpmodeStat          int32    `protobuf:"varint,14,opt,name=tcpmode_stat,json=tcpmodeStat,proto3" json:"tcpmode_stat,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MyMsg) Reset()         { *m = MyMsg{} }
func (m *MyMsg) String() string { return proto.CompactTextString(m) }
func (*MyMsg) ProtoMessage()    {}
func (*MyMsg) Descriptor() ([]byte, []int) {
	return fileDescriptor_c06e4cca6c2cc899, []int{0}
}

func (m *MyMsg) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MyMsg.Unmarshal(m, b)
}
func (m *MyMsg) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MyMsg.Marshal(b, m, deterministic)
}
func (m *MyMsg) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MyMsg.Merge(m, src)
}
func (m *MyMsg) XXX_Size() int {
	return xxx_messageInfo_MyMsg.Size(m)
}
func (m *MyMsg) XXX_DiscardUnknown() {
	xxx_messageInfo_MyMsg.DiscardUnknown(m)
}

var xxx_messageInfo_MyMsg proto.InternalMessageInfo

func (m *MyMsg) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *MyMsg) GetType() int32 {
	if m != nil {
		return m.Type
	}
	return 0
}

func (m *MyMsg) GetTarget() string {
	if m != nil {
		return m.Target
	}
	return ""
}

func (m *MyMsg) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *MyMsg) GetRproto() int32 {
	if m != nil {
		return m.Rproto
	}
	return 0
}

func (m *MyMsg) GetMagic() int32 {
	if m != nil {
		return m.Magic
	}
	return 0
}

func (m *MyMsg) GetKey() int32 {
	if m != nil {
		return m.Key
	}
	return 0
}

func (m *MyMsg) GetTimeout() int32 {
	if m != nil {
		return m.Timeout
	}
	return 0
}

func (m *MyMsg) GetTcpmode() int32 {
	if m != nil {
		return m.Tcpmode
	}
	return 0
}

func (m *MyMsg) GetTcpmodeBuffersize() int32 {
	if m != nil {
		return m.TcpmodeBuffersize
	}
	return 0
}

func (m *MyMsg) GetTcpmodeMaxwin() int32 {
	if m != nil {
		return m.TcpmodeMaxwin
	}
	return 0
}

func (m *MyMsg) GetTcpmodeResendTimems() int32 {
	if m != nil {
		return m.TcpmodeResendTimems
	}
	return 0
}

func (m *MyMsg) GetTcpmodeCompress() int32 {
	if m != nil {
		return m.TcpmodeCompress
	}
	return 0
}

func (m *MyMsg) GetTcpmodeStat() int32 {
	if m != nil {
		return m.TcpmodeStat
	}
	return 0
}

func init() {
	proto.RegisterEnum("MyMsg_TYPE",MyMsg_TYPE_name, MyMsg_TYPE_value)
	proto.RegisterType((*MyMsg)(nil), "MyMsg")
}

func init() { proto.RegisterFile("msg.proto", fileDescriptor_c06e4cca6c2cc899) }

var fileDescriptor_c06e4cca6c2cc899 = []byte{
	// 342 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x3c, 0x90, 0xdb, 0x6a, 0xe2, 0x50,
	0x14, 0x86, 0x27, 0x27, 0x0f, 0xcb, 0xe8, 0xc4, 0x35, 0x07, 0xd6, 0x65, 0x46, 0x18, 0xc8, 0x5c,
	0xcc, 0xc0, 0xb4, 0x4f, 0xa0, 0xb6, 0x88, 0x48, 0x8a, 0xa4, 0xde, 0xb4, 0x37, 0x12, 0xcd, 0x36,
	0x84, 0x36, 0x07, 0xb2, 0xb7, 0xb4, 0xf6, 0x9d, 0xfa, 0x08, 0x7d, 0x8d, 0x3e, 0x4f, 0xc9, 0x72,
	0xa7, 0x77, 0xff, 0xff, 0x7f, 0x5f, 0xc8, 0x62, 0x43, 0x3f, 0x97, 0xe9, 0xbf, 0xaa, 0x2e, 0x55,
	0x39, 0x79, 0xb7, 0xc0, 0x09, 0x4f, 0xa1, 0x4c, 0x71, 0x04, 0x66, 0x96, 0x90, 0xe1, 0x1b, 0x41,
	0x3f, 0x32, 0xb3, 0x04, 0x11, 0x6c, 0x75, 0xaa, 0x04, 0x99, 0xbe, 0x11, 0x38, 0x11, 0x67, 0xfc,
	0x09, 0x1d, 0x15, 0xd7, 0xa9, 0x50, 0x64, 0xb1, 0xa7, 0x5b, 0xe3, 0x26, 0xb1, 0x8a, 0xc9, 0xf6,
	0x8d, 0xc0, 0x8d, 0x38, 0x37, 0x6e, 0xcd, 0xff, 0x20, 0xc7, 0x37, 0x82, 0x71, 0xa4, 0x1b, 0x7e,
	0x07, 0x27, 0x8f, 0xd3, 0x6c, 0x4f, 0x1d, 0x9e, 0xcf, 0x05, 0x3d, 0xb0, 0x1e, 0xc4, 0x89, 0xba,
	0xbc, 0x35, 0x11, 0x09, 0xba, 0x2a, 0xcb, 0x45, 0x79, 0x54, 0xd4, 0xe3, 0x13, 0xda, 0xca, 0x64,
	0x5f, 0xe5, 0x65, 0x22, 0xa8, 0xaf, 0xc9, 0xb9, 0xe2, 0x5f, 0x40, 0x1d, 0xb7, 0xbb, 0xe3, 0xe1,
	0x20, 0x6a, 0x99, 0xbd, 0x08, 0x02, 0x96, 0xc6, 0x9a, 0xcc, 0x3e, 0x01, 0xfe, 0x86, 0x51, 0xab,
	0xe7, 0xf1, 0xf3, 0x53, 0x56, 0xd0, 0x80, 0xd5, 0xa1, 0x5e, 0x43, 0x1e, 0xf1, 0x02, 0x7e, 0xb4,
	0x5a, 0x2d, 0xa4, 0x28, 0x92, 0x6d, 0x73, 0x49, 0x2e, 0xc9, 0x65, 0xfb, 0x9b, 0x86, 0x11, 0xb3,
	0x0d, 0x23, 0xfc, 0x03, 0x5e, 0xfb, 0xcd, 0xbe, 0xcc, 0xab, 0x5a, 0x48, 0x49, 0x43, 0xd6, 0xbf,
	0xea, 0x7d, 0xae, 0x67, 0xfc, 0x05, 0x6e, 0xab, 0x4a, 0x15, 0x2b, 0x1a, 0xb1, 0x36, 0xd0, 0xdb,
	0xad, 0x8a, 0xd5, 0xe4, 0x3f, 0xd8, 0x9b, 0xbb, 0xf5, 0x35, 0xf6, 0xc0, 0xbe, 0x9a, 0x6e, 0xa6,
	0xde, 0x97, 0x26, 0xad, 0x97, 0x37, 0x0b, 0xcf, 0x68, 0xd2, 0x6a, 0x39, 0x5f, 0x79, 0x26, 0x0e,
	0xc0, 0x09, 0xa7, 0x8b, 0xe5, 0xdc, 0x7b, 0x7d, 0xb3, 0x66, 0xee, 0x3d, 0x54, 0x59, 0x91, 0xaa,
	0x63, 0x51, 0x88, 0xc7, 0x5d, 0x87, 0xdf, 0xfe, 0xf2, 0x23, 0x00, 0x00, 0xff, 0xff, 0x59, 0xbc,
	0x55, 0x76, 0xfa, 0x01, 0x00, 0x00,
}
