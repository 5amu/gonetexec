package msrpc

import (
	"github.com/5amu/gonetexec/pkg/smb/internal/utf16le"
)

// e1af8308-5d1f-11c9-91a4-08002b14a0fa
//var EPMv4_UUID = []byte("0883afe11f5dc91191a408002b14a0fa")

var SVCCTL_UUID = []byte("81bb7a364498f135ad3298f038001003")

const (
	SVCCTL_VERSION       = 2
	SVCCTL_VERSION_MINOR = 0

	SVCCTL_DLL = "svcctl"
)

// opnum
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/0d7a7011-9f41-470d-ad52-8535b47ac282
const (
	RCloseServiceHandle         = 0
	RControlService             = 1
	RDeleteService              = 2
	RLockServiceDatabase        = 3
	RQueryServiceObjectSecurity = 4
	RSetServiceObjectSecurity   = 5
	RQueryServiceStatus         = 6
	RSetServiceStatus           = 7
	RUnlockServiceDatabase      = 8
	RNotifyBootConfigStatus     = 9
	RChangeServiceConfigW       = 11
	RCreateServiceW             = 12
	REnumDependentServicesW     = 13
	REnumServicesStatusW        = 14
	ROpenSCManagerW             = 15
	ROpenServiceW               = 16
	RQueryServiceConfigW        = 17
	RQueryServiceLockStatusW    = 18
	RStartServiceW              = 19
	RGetServiceDisplayNameW     = 20
	RGetServiceKeyNameW         = 21
	RChangeServiceConfigA       = 23
	RCreateServiceA             = 24
	REnumDependentServicesA     = 25
	REnumServicesStatusA        = 26
	ROpenSCManagerA             = 27
	ROpenServiceA               = 28
	RQueryServiceConfigA        = 29
	RQueryServiceLockStatusA    = 30
	RStartServiceA              = 31
	RGetServiceDisplayNameA     = 32
	RGetServiceKeyNameA         = 33
	REnumServiceGroupW          = 35
	RChangeServiceConfig2A      = 36
	RChangeServiceConfig2W      = 37
	RQueryServiceConfig2A       = 38
	RQueryServiceConfig2W       = 39
	RQueryServiceStatusEx       = 40
	REnumServicesStatusExA      = 41
	REnumServicesStatusExW      = 42
	RCreateServiceWOW64A        = 44
	RCreateServiceWOW64W        = 45
	RNotifyServiceStatusChange  = 47
	RGetNotifyResults           = 48
	RCloseNotifyHandle          = 49
	RControlServiceExA          = 50
	RControlServiceExW          = 51
	RQueryServiceConfigEx       = 56
	RCreateWowService           = 60
	ROpenSCManager2             = 64
)

// access request
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/0d7a7011-9f41-470d-ad52-8535b47ac282
const (
	SERVICE_ALL_ACCESS        = 0x000F01FF
	SC_MANAGER_CREATE_SERVICE = 0x00000002
	SC_MANAGER_CONNECT        = 0x00000001
)

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/6a8ca926-9477-4dd4-b766-692fab07227e
const (
	SERVICE_KERNEL_DRIVER       = 0x00000001
	SERVICE_FILE_SYSTEM_DRIVER  = 0x00000002
	SERVICE_WIN32_OWN_PROCESS   = 0x00000010
	SERVICE_WIN32_SHARE_PROCESS = 0x00000020
	SERVICE_INTERACTIVE_PROCESS = 0x00000100
)

// Service Start Type
const (
	SERVICE_BOOT_START   = 0x00000000
	SERVICE_SYSTEM_START = 0x00000001
	SERVICE_AUTO_START   = 0x00000002
	SERVICE_DEMAND_START = 0x00000003
	SERVICE_DISABLED     = 0x00000004
)

// Service Error Control
const (
	SERVICE_ERROR_IGNORE   = 0x00000000
	SERVICE_ERROR_NORMAL   = 0x00000001
	SERVICE_ERROR_SEVERE   = 0x00000002
	SERVICE_ERROR_CRITICAL = 0x00000003
)

type SVCCTLHandle struct {
	ReferentId  uint32 `smb:"offset:Data"`
	MaxCount    uint32
	Offset      uint32
	ActualCount uint32
	Data        []byte
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/dc84adb3-d51d-48eb-820d-ba1c6ca5faf2
type OpenSCManagerRequest struct {
	MachineName  SVCCTLHandle
	DatabaseName SVCCTLHandle
	Reserved     uint16
	AccessMask   uint32
}

type OpenSCManagerResponse struct {
	RpcHeaderStruct
	AllocHint     uint32
	ContextId     uint16
	CancelCount   uint8
	Reserved      uint8
	ContextHandle []byte `smb:"fixed:20"`
	ReturnCode    uint32
}

type OpenSCManager struct {
	CallId     uint32
	ServerName string
}

func (r *OpenSCManager) Size() int {
	off := utf16le.EncodedStringLen(r.ServerName + "\x00")
	off += off % 4
	off += utf16le.EncodedStringLen("ServicesActive\x00")
	off += off % 4

	off += 16      // Rpc base header
	off += 2       // context ID
	off += 2       // Opnum
	off += 16 + 16 // fixed bytes of the 2 handles
	off += 4       // access mask
	off += 4
	return off
}

func (r *OpenSCManager) Encode(b []byte) {
	srvname, srvcount := utf16lePlusCount(r.ServerName)
	dbname, dbcount := utf16lePlusCount("ServicesActive")

	req := RpcRequestStruct{
		RpcHeaderStruct: RpcHeaderStruct{
			RpcVersion:         RPC_VERSION,
			RpcVersionMinor:    RPC_VERSION_MINOR,
			PacketType:         RPC_TYPE_REQUEST,
			PacketFlags:        RPC_PACKET_FLAG_FIRST | RPC_PACKET_FLAG_LAST,
			DataRepresentation: []byte{0x10, 0, 0, 0},
			AuthLength:         0,
			CallId:             r.CallId,
		},
		ContextID: 0,
		OpNum:     ROpenSCManagerW,
		Payload: OpenSCManagerRequest{
			MachineName: SVCCTLHandle{
				MaxCount:    uint32(srvcount),
				Offset:      0,
				ActualCount: uint32(srvcount),
				Data:        srvname,
			},
			DatabaseName: SVCCTLHandle{
				MaxCount:    uint32(dbcount),
				Offset:      0,
				ActualCount: uint32(dbcount),
				Data:        dbname,
			},
			Reserved:   0xbfbf,
			AccessMask: SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT,
		},
	}
	copy(b, req.Bytes())
}

type SCRpcHandle struct {
	MaxCount    uint32
	Offset      uint32
	ActualCount uint32
	Data        []byte
}

type OpenServiceRequest struct {
	ContextHandle []byte `smb:"fixed:20"`
	ServiceName   SCRpcHandle
	Reserved      uint16
	AccessMask    uint32
}

type OpenServiceResponse struct {
	RpcHeaderStruct
	AllocHint     uint32
	ContextId     uint16
	CancelCount   uint8
	Reserved      uint8
	ContextHandle []byte `smb:"fixed:20"`
	ReturnCode    uint32
}

type OpenService struct {
	CallId        uint32
	ServiceName   string
	ContextHandle []byte `smb:"fixed:20"`
}

func (r *OpenService) Size() int {
	off := utf16le.EncodedStringLen(r.ServiceName) + 2
	off = roundup(off, 4)
	off += 16 // Rpc base header
	off += 2  // context ID
	off += 2  // Opnum
	off += 20 // Context Handle
	off += 16 // SVC Handle size
	off += 4  // accessmask
	return off
}

func (r *OpenService) Encode(b []byte) {
	srvname, srvcount := utf16lePlusCount(r.ServiceName)

	req := RpcRequestStruct{
		RpcHeaderStruct: RpcHeaderStruct{
			RpcVersion:         RPC_VERSION,
			RpcVersionMinor:    RPC_VERSION_MINOR,
			PacketType:         RPC_TYPE_REQUEST,
			PacketFlags:        RPC_PACKET_FLAG_FIRST | RPC_PACKET_FLAG_LAST,
			DataRepresentation: []byte{0x10, 0, 0, 0},
			AuthLength:         0,
			CallId:             r.CallId,
		},
		ContextID: 0,
		OpNum:     ROpenServiceW,
		Payload: OpenServiceRequest{
			ContextHandle: r.ContextHandle,
			ServiceName: SCRpcHandle{
				MaxCount:    uint32(srvcount),
				Offset:      0,
				ActualCount: uint32(srvcount),
				Data:        srvname,
			},
			AccessMask: SERVICE_ALL_ACCESS,
		},
	}
	copy(b, req.Bytes())
}

type CreateServiceRequest struct {
	ContextHandle       []byte `smb:"fixed:20"`
	ServiceName         SCRpcHandle
	Reserved1           uint16
	DisplayName         SVCCTLHandle
	Reserved2           uint16
	AccessMask          uint32
	ServiceType         uint32
	ServiceStartType    uint32
	ServiceErrorControl uint32
	BinaryPathName      SCRpcHandle
	NULLPointer         uint32
	TagId               uint32
	NULLPointer2        uint32
	DependSize          uint32
	NULLPointer3        uint32
	NULLPointer4        uint32
	PasswordSize        uint32
}

type CreateServiceResponse struct {
	RpcHeaderStruct
	AllocHint     uint32
	ContextId     uint16
	CancelCount   uint8
	Reserved      uint8
	TagId         uint32
	ContextHandle []byte `smb:"fixed:20"`
	ReturnCode    uint32
}

type CreateService struct {
	CallId         uint32
	ServiceName    string
	DisplayName    string
	BinaryPathName string
	ContextHandle  []byte `smb:"fixed:20"`
}

func (r *CreateService) Size() int {
	off := utf16le.EncodedStringLen(r.ServiceName) + 2
	off += utf16le.EncodedStringLen(r.DisplayName) + 2
	off += utf16le.EncodedStringLen(r.BinaryPathName) + 2
	off = roundup(off, 4)
	off += 16           // Rpc base header
	off += 2            // context ID
	off += 2            // Opnum
	off += 20           // Context Handle
	off += 16 + 16 + 20 // SVC Handle size
	off += 4            // accessmask
	off += 4            // ServiceType
	off += 4            // ServiceStartType
	off += 4            // ServiceErrorControl
	return off + 24     // following data
}

func (r *CreateService) Encode(b []byte) {
	sname, scount := utf16lePlusCount(r.ServiceName)
	dname, dcount := utf16lePlusCount(r.DisplayName)
	bname, bcount := utf16lePlusCount(r.BinaryPathName)

	req := RpcRequestStruct{
		RpcHeaderStruct: RpcHeaderStruct{
			RpcVersion:         RPC_VERSION,
			RpcVersionMinor:    RPC_VERSION_MINOR,
			PacketType:         RPC_TYPE_REQUEST,
			PacketFlags:        RPC_PACKET_FLAG_FIRST | RPC_PACKET_FLAG_LAST,
			DataRepresentation: []byte{0x10, 0, 0, 0},
			AuthLength:         0,
			CallId:             r.CallId,
		},
		ContextID: 0,
		OpNum:     RCreateServiceW,
		Payload: CreateServiceRequest{
			ContextHandle: r.ContextHandle,
			ServiceName: SCRpcHandle{
				MaxCount:    uint32(scount),
				Offset:      0,
				ActualCount: uint32(scount),
				Data:        sname,
			},
			DisplayName: SVCCTLHandle{
				MaxCount:    uint32(dcount),
				Offset:      0,
				ActualCount: uint32(dcount),
				Data:        dname,
			},
			AccessMask:          SERVICE_ALL_ACCESS,
			ServiceType:         SERVICE_WIN32_OWN_PROCESS,
			ServiceStartType:    SERVICE_DEMAND_START,
			ServiceErrorControl: SERVICE_ERROR_IGNORE,
			BinaryPathName: SCRpcHandle{
				MaxCount:    uint32(bcount),
				Offset:      0,
				ActualCount: uint32(bcount),
				Data:        bname,
			},
		},
	}
	copy(b, req.Bytes())
}

type StartServiceRequest struct {
	ContextHandle []byte `smb:"fixed:20"`
	Argc          uint32
	Argv          []byte `smb:"fixed:4"`
}

type StartServiceResponse struct {
	RpcHeaderStruct
	AllocHint   uint32
	ContextId   uint16
	CancelCount uint8
	Reserved    uint8
	StubData    uint32
}

type StartService struct {
	ContextHandle []byte `smb:"fixed:20"`
	CallId        uint32
}

func (r *StartService) Size() int {
	off := 16 // Rpc base header
	off += 2  // context ID
	off += 2  // Opnum
	off += 20 // Service Handle
	off += 4  // Argc
	off += 4  // Argv
	return off + 4
}

func (r *StartService) Encode(b []byte) {
	req := RpcRequestStruct{
		RpcHeaderStruct: RpcHeaderStruct{
			RpcVersion:         RPC_VERSION,
			RpcVersionMinor:    RPC_VERSION_MINOR,
			PacketType:         RPC_TYPE_REQUEST,
			PacketFlags:        RPC_PACKET_FLAG_FIRST | RPC_PACKET_FLAG_LAST,
			DataRepresentation: []byte{0x10, 0, 0, 0},
			AuthLength:         0,
			CallId:             r.CallId,
		},
		ContextID: 0,
		OpNum:     RStartServiceW,
		Payload: StartServiceRequest{
			ContextHandle: r.ContextHandle,
			Argc:          0,
			Argv:          []byte{0, 0, 0, 0},
		},
	}
	copy(b, req.Bytes())
}

type DeleteServiceRequest struct {
	ContextHandle []byte `smb:"fixed:20"`
}

type DeleteServiceResponse struct {
	RpcHeaderStruct
	AllocHint   uint32
	ContextId   uint16
	CancelCount uint8
	Reserved    uint8
	ReturnCode  uint32
}

type DeleteService struct {
	ContextHandle []byte
	CallId        uint32
}

func (r *DeleteService) Size() int {
	off := 16 // Rpc base header
	off += 2  // context ID
	off += 4  // Alloc Hint
	off += 2  // Opnum
	off += 20 // ContextHandle
	return off
}

func (r *DeleteService) Encode(b []byte) {
	req := RpcRequestStruct{
		RpcHeaderStruct: RpcHeaderStruct{
			RpcVersion:         RPC_VERSION,
			RpcVersionMinor:    RPC_VERSION_MINOR,
			PacketType:         RPC_TYPE_REQUEST,
			PacketFlags:        RPC_PACKET_FLAG_FIRST | RPC_PACKET_FLAG_LAST,
			DataRepresentation: []byte{0x10, 0, 0, 0},
			AuthLength:         0,
			CallId:             r.CallId,
		},
		ContextID: 0,
		OpNum:     RDeleteService,
		Payload: DeleteServiceRequest{
			ContextHandle: r.ContextHandle,
		},
	}
	copy(b, req.Bytes())
}
