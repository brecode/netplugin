// Package l2 represents the VPP binary API of the 'l2' VPP module.
// DO NOT EDIT. Generated from '/usr/share/vpp/api/l2.api.json'
package l2

import "git.fd.io/govpp.git/api"

// VlApiVersion contains version of the API.
const VlAPIVersion = 0x7bf05f3c

// MacEntry represents the VPP binary API data type 'mac_entry'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 3:
//
//        ["mac_entry",
//            ["u32", "sw_if_index"],
//            ["u8", "mac_addr", 6],
//            ["u8", "is_del"],
//            ["u8", "spare"],
//            {"crc" : "0xa741caef"}
//        ],
//
type MacEntry struct {
	SwIfIndex uint32
	MacAddr   []byte `struc:"[6]byte"`
	IsDel     uint8
	Spare     uint8
}

func (*MacEntry) GetTypeName() string {
	return "mac_entry"
}
func (*MacEntry) GetCrcString() string {
	return "a741caef"
}

// BridgeDomainSwIf represents the VPP binary API data type 'bridge_domain_sw_if'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 10:
//
//        ["bridge_domain_sw_if",
//            ["u32", "context"],
//            ["u32", "sw_if_index"],
//            ["u8", "shg"],
//            {"crc" : "0x89a002d4"}
//        ]
//
type BridgeDomainSwIf struct {
	SwIfIndex uint32
	Shg       uint8
}

func (*BridgeDomainSwIf) GetTypeName() string {
	return "bridge_domain_sw_if"
}
func (*BridgeDomainSwIf) GetCrcString() string {
	return "89a002d4"
}

// L2XconnectDetails represents the VPP binary API message 'l2_xconnect_details'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 18:
//
//        ["l2_xconnect_details",
//            ["u16", "_vl_msg_id"],
//            ["u32", "context"],
//            ["u32", "rx_sw_if_index"],
//            ["u32", "tx_sw_if_index"],
//            {"crc" : "0x8983dff7"}
//        ],
//
type L2XconnectDetails struct {
	RxSwIfIndex uint32
	TxSwIfIndex uint32
}

func (*L2XconnectDetails) GetMessageName() string {
	return "l2_xconnect_details"
}
func (*L2XconnectDetails) GetMessageType() api.MessageType {
	return api.ReplyMessage
}
func (*L2XconnectDetails) GetCrcString() string {
	return "8983dff7"
}
func NewL2XconnectDetails() api.Message {
	return &L2XconnectDetails{}
}

// L2XconnectDump represents the VPP binary API message 'l2_xconnect_dump'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 25:
//
//        ["l2_xconnect_dump",
//            ["u16", "_vl_msg_id"],
//            ["u32", "client_index"],
//            ["u32", "context"],
//            {"crc" : "0x794eaafb"}
//        ],
//
type L2XconnectDump struct {
}

func (*L2XconnectDump) GetMessageName() string {
	return "l2_xconnect_dump"
}
func (*L2XconnectDump) GetMessageType() api.MessageType {
	return api.RequestMessage
}
func (*L2XconnectDump) GetCrcString() string {
	return "794eaafb"
}
func NewL2XconnectDump() api.Message {
	return &L2XconnectDump{}
}

// L2FibTableDetails represents the VPP binary API message 'l2_fib_table_details'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 31:
//
//        ["l2_fib_table_details",
//            ["u16", "_vl_msg_id"],
//            ["u32", "context"],
//            ["u32", "bd_id"],
//            ["u64", "mac"],
//            ["u32", "sw_if_index"],
//            ["u8", "static_mac"],
//            ["u8", "filter_mac"],
//            ["u8", "bvi_mac"],
//            {"crc" : "0x07426ad7"}
//        ],
//
type L2FibTableDetails struct {
	BdID      uint32
	Mac       uint64
	SwIfIndex uint32
	StaticMac uint8
	FilterMac uint8
	BviMac    uint8
}

func (*L2FibTableDetails) GetMessageName() string {
	return "l2_fib_table_details"
}
func (*L2FibTableDetails) GetMessageType() api.MessageType {
	return api.ReplyMessage
}
func (*L2FibTableDetails) GetCrcString() string {
	return "07426ad7"
}
func NewL2FibTableDetails() api.Message {
	return &L2FibTableDetails{}
}

// L2FibTableDump represents the VPP binary API message 'l2_fib_table_dump'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 42:
//
//        ["l2_fib_table_dump",
//            ["u16", "_vl_msg_id"],
//            ["u32", "client_index"],
//            ["u32", "context"],
//            ["u32", "bd_id"],
//            {"crc" : "0xedcbdcf6"}
//        ],
//
type L2FibTableDump struct {
	BdID uint32
}

func (*L2FibTableDump) GetMessageName() string {
	return "l2_fib_table_dump"
}
func (*L2FibTableDump) GetMessageType() api.MessageType {
	return api.RequestMessage
}
func (*L2FibTableDump) GetCrcString() string {
	return "edcbdcf6"
}
func NewL2FibTableDump() api.Message {
	return &L2FibTableDump{}
}

// L2FibClearTable represents the VPP binary API message 'l2_fib_clear_table'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 49:
//
//        ["l2_fib_clear_table",
//            ["u16", "_vl_msg_id"],
//            ["u32", "client_index"],
//            ["u32", "context"],
//            {"crc" : "0x40dc61e3"}
//        ],
//
type L2FibClearTable struct {
}

func (*L2FibClearTable) GetMessageName() string {
	return "l2_fib_clear_table"
}
func (*L2FibClearTable) GetMessageType() api.MessageType {
	return api.RequestMessage
}
func (*L2FibClearTable) GetCrcString() string {
	return "40dc61e3"
}
func NewL2FibClearTable() api.Message {
	return &L2FibClearTable{}
}

// L2FibClearTableReply represents the VPP binary API message 'l2_fib_clear_table_reply'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 55:
//
//        ["l2_fib_clear_table_reply",
//            ["u16", "_vl_msg_id"],
//            ["u32", "context"],
//            ["i32", "retval"],
//            {"crc" : "0x0425b038"}
//        ],
//
type L2FibClearTableReply struct {
	Retval int32
}

func (*L2FibClearTableReply) GetMessageName() string {
	return "l2_fib_clear_table_reply"
}
func (*L2FibClearTableReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}
func (*L2FibClearTableReply) GetCrcString() string {
	return "0425b038"
}
func NewL2FibClearTableReply() api.Message {
	return &L2FibClearTableReply{}
}

// L2fibFlushAll represents the VPP binary API message 'l2fib_flush_all'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 61:
//
//        ["l2fib_flush_all",
//            ["u16", "_vl_msg_id"],
//            ["u32", "client_index"],
//            ["u32", "context"],
//            {"crc" : "0xabc3e39e"}
//        ],
//
type L2fibFlushAll struct {
}

func (*L2fibFlushAll) GetMessageName() string {
	return "l2fib_flush_all"
}
func (*L2fibFlushAll) GetMessageType() api.MessageType {
	return api.RequestMessage
}
func (*L2fibFlushAll) GetCrcString() string {
	return "abc3e39e"
}
func NewL2fibFlushAll() api.Message {
	return &L2fibFlushAll{}
}

// L2fibFlushAllReply represents the VPP binary API message 'l2fib_flush_all_reply'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 67:
//
//        ["l2fib_flush_all_reply",
//            ["u16", "_vl_msg_id"],
//            ["u32", "context"],
//            ["i32", "retval"],
//            {"crc" : "0xef3a3245"}
//        ],
//
type L2fibFlushAllReply struct {
	Retval int32
}

func (*L2fibFlushAllReply) GetMessageName() string {
	return "l2fib_flush_all_reply"
}
func (*L2fibFlushAllReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}
func (*L2fibFlushAllReply) GetCrcString() string {
	return "ef3a3245"
}
func NewL2fibFlushAllReply() api.Message {
	return &L2fibFlushAllReply{}
}

// L2fibFlushBd represents the VPP binary API message 'l2fib_flush_bd'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 73:
//
//        ["l2fib_flush_bd",
//            ["u16", "_vl_msg_id"],
//            ["u32", "client_index"],
//            ["u32", "context"],
//            ["u32", "bd_id"],
//            {"crc" : "0x82b7f182"}
//        ],
//
type L2fibFlushBd struct {
	BdID uint32
}

func (*L2fibFlushBd) GetMessageName() string {
	return "l2fib_flush_bd"
}
func (*L2fibFlushBd) GetMessageType() api.MessageType {
	return api.RequestMessage
}
func (*L2fibFlushBd) GetCrcString() string {
	return "82b7f182"
}
func NewL2fibFlushBd() api.Message {
	return &L2fibFlushBd{}
}

// L2fibFlushBdReply represents the VPP binary API message 'l2fib_flush_bd_reply'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 80:
//
//        ["l2fib_flush_bd_reply",
//            ["u16", "_vl_msg_id"],
//            ["u32", "context"],
//            ["i32", "retval"],
//            {"crc" : "0xa68d5609"}
//        ],
//
type L2fibFlushBdReply struct {
	Retval int32
}

func (*L2fibFlushBdReply) GetMessageName() string {
	return "l2fib_flush_bd_reply"
}
func (*L2fibFlushBdReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}
func (*L2fibFlushBdReply) GetCrcString() string {
	return "a68d5609"
}
func NewL2fibFlushBdReply() api.Message {
	return &L2fibFlushBdReply{}
}

// L2fibFlushInt represents the VPP binary API message 'l2fib_flush_int'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 86:
//
//        ["l2fib_flush_int",
//            ["u16", "_vl_msg_id"],
//            ["u32", "client_index"],
//            ["u32", "context"],
//            ["u32", "sw_if_index"],
//            {"crc" : "0xa1216623"}
//        ],
//
type L2fibFlushInt struct {
	SwIfIndex uint32
}

func (*L2fibFlushInt) GetMessageName() string {
	return "l2fib_flush_int"
}
func (*L2fibFlushInt) GetMessageType() api.MessageType {
	return api.RequestMessage
}
func (*L2fibFlushInt) GetCrcString() string {
	return "a1216623"
}
func NewL2fibFlushInt() api.Message {
	return &L2fibFlushInt{}
}

// L2fibFlushIntReply represents the VPP binary API message 'l2fib_flush_int_reply'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 93:
//
//        ["l2fib_flush_int_reply",
//            ["u16", "_vl_msg_id"],
//            ["u32", "context"],
//            ["i32", "retval"],
//            {"crc" : "0xaacfc0d0"}
//        ],
//
type L2fibFlushIntReply struct {
	Retval int32
}

func (*L2fibFlushIntReply) GetMessageName() string {
	return "l2fib_flush_int_reply"
}
func (*L2fibFlushIntReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}
func (*L2fibFlushIntReply) GetCrcString() string {
	return "aacfc0d0"
}
func NewL2fibFlushIntReply() api.Message {
	return &L2fibFlushIntReply{}
}

// L2fibAddDel represents the VPP binary API message 'l2fib_add_del'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 99:
//
//        ["l2fib_add_del",
//            ["u16", "_vl_msg_id"],
//            ["u32", "client_index"],
//            ["u32", "context"],
//            ["u64", "mac"],
//            ["u32", "bd_id"],
//            ["u32", "sw_if_index"],
//            ["u8", "is_add"],
//            ["u8", "static_mac"],
//            ["u8", "filter_mac"],
//            ["u8", "bvi_mac"],
//            {"crc" : "0x604cc582"}
//        ],
//
type L2fibAddDel struct {
	Mac       uint64
	BdID      uint32
	SwIfIndex uint32
	IsAdd     uint8
	StaticMac uint8
	FilterMac uint8
	BviMac    uint8
}

func (*L2fibAddDel) GetMessageName() string {
	return "l2fib_add_del"
}
func (*L2fibAddDel) GetMessageType() api.MessageType {
	return api.RequestMessage
}
func (*L2fibAddDel) GetCrcString() string {
	return "604cc582"
}
func NewL2fibAddDel() api.Message {
	return &L2fibAddDel{}
}

// L2fibAddDelReply represents the VPP binary API message 'l2fib_add_del_reply'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 112:
//
//        ["l2fib_add_del_reply",
//            ["u16", "_vl_msg_id"],
//            ["u32", "context"],
//            ["i32", "retval"],
//            {"crc" : "0x1be0875a"}
//        ],
//
type L2fibAddDelReply struct {
	Retval int32
}

func (*L2fibAddDelReply) GetMessageName() string {
	return "l2fib_add_del_reply"
}
func (*L2fibAddDelReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}
func (*L2fibAddDelReply) GetCrcString() string {
	return "1be0875a"
}
func NewL2fibAddDelReply() api.Message {
	return &L2fibAddDelReply{}
}

// WantL2MacsEvents represents the VPP binary API message 'want_l2_macs_events'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 118:
//
//        ["want_l2_macs_events",
//            ["u16", "_vl_msg_id"],
//            ["u32", "client_index"],
//            ["u32", "context"],
//            ["u32", "learn_limit"],
//            ["u8", "scan_delay"],
//            ["u8", "max_macs_in_event"],
//            ["u8", "enable_disable"],
//            ["u32", "pid"],
//            {"crc" : "0xc043c52c"}
//        ],
//
type WantL2MacsEvents struct {
	LearnLimit     uint32
	ScanDelay      uint8
	MaxMacsInEvent uint8
	EnableDisable  uint8
	Pid            uint32
}

func (*WantL2MacsEvents) GetMessageName() string {
	return "want_l2_macs_events"
}
func (*WantL2MacsEvents) GetMessageType() api.MessageType {
	return api.RequestMessage
}
func (*WantL2MacsEvents) GetCrcString() string {
	return "c043c52c"
}
func NewWantL2MacsEvents() api.Message {
	return &WantL2MacsEvents{}
}

// WantL2MacsEventsReply represents the VPP binary API message 'want_l2_macs_events_reply'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 129:
//
//        ["want_l2_macs_events_reply",
//            ["u16", "_vl_msg_id"],
//            ["u32", "context"],
//            ["i32", "retval"],
//            {"crc" : "0x97d6535f"}
//        ],
//
type WantL2MacsEventsReply struct {
	Retval int32
}

func (*WantL2MacsEventsReply) GetMessageName() string {
	return "want_l2_macs_events_reply"
}
func (*WantL2MacsEventsReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}
func (*WantL2MacsEventsReply) GetCrcString() string {
	return "97d6535f"
}
func NewWantL2MacsEventsReply() api.Message {
	return &WantL2MacsEventsReply{}
}

// L2MacsEvent represents the VPP binary API message 'l2_macs_event'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 135:
//
//        ["l2_macs_event",
//            ["u16", "_vl_msg_id"],
//            ["u32", "client_index"],
//            ["u32", "pid"],
//            ["u32", "n_macs"],
//            ["vl_api_mac_entry_t", "mac", 0, "n_macs"],
//            {"crc" : "0x2a1cc4f5"}
//        ],
//
type L2MacsEvent struct {
	Pid   uint32
	NMacs uint32 `struc:"sizeof=Mac"`
	Mac   []MacEntry
}

func (*L2MacsEvent) GetMessageName() string {
	return "l2_macs_event"
}
func (*L2MacsEvent) GetMessageType() api.MessageType {
	return api.RequestMessage
}
func (*L2MacsEvent) GetCrcString() string {
	return "2a1cc4f5"
}
func NewL2MacsEvent() api.Message {
	return &L2MacsEvent{}
}

// L2Flags represents the VPP binary API message 'l2_flags'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 143:
//
//        ["l2_flags",
//            ["u16", "_vl_msg_id"],
//            ["u32", "client_index"],
//            ["u32", "context"],
//            ["u32", "sw_if_index"],
//            ["u8", "is_set"],
//            ["u32", "feature_bitmap"],
//            {"crc" : "0x987fb8e1"}
//        ],
//
type L2Flags struct {
	SwIfIndex     uint32
	IsSet         uint8
	FeatureBitmap uint32
}

func (*L2Flags) GetMessageName() string {
	return "l2_flags"
}
func (*L2Flags) GetMessageType() api.MessageType {
	return api.RequestMessage
}
func (*L2Flags) GetCrcString() string {
	return "987fb8e1"
}
func NewL2Flags() api.Message {
	return &L2Flags{}
}

// L2FlagsReply represents the VPP binary API message 'l2_flags_reply'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 152:
//
//        ["l2_flags_reply",
//            ["u16", "_vl_msg_id"],
//            ["u32", "context"],
//            ["i32", "retval"],
//            ["u32", "resulting_feature_bitmap"],
//            {"crc" : "0xbd749594"}
//        ],
//
type L2FlagsReply struct {
	Retval                 int32
	ResultingFeatureBitmap uint32
}

func (*L2FlagsReply) GetMessageName() string {
	return "l2_flags_reply"
}
func (*L2FlagsReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}
func (*L2FlagsReply) GetCrcString() string {
	return "bd749594"
}
func NewL2FlagsReply() api.Message {
	return &L2FlagsReply{}
}

// BridgeDomainSetMacAge represents the VPP binary API message 'bridge_domain_set_mac_age'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 159:
//
//        ["bridge_domain_set_mac_age",
//            ["u16", "_vl_msg_id"],
//            ["u32", "client_index"],
//            ["u32", "context"],
//            ["u32", "bd_id"],
//            ["u8", "mac_age"],
//            {"crc" : "0xf58c37aa"}
//        ],
//
type BridgeDomainSetMacAge struct {
	BdID   uint32
	MacAge uint8
}

func (*BridgeDomainSetMacAge) GetMessageName() string {
	return "bridge_domain_set_mac_age"
}
func (*BridgeDomainSetMacAge) GetMessageType() api.MessageType {
	return api.RequestMessage
}
func (*BridgeDomainSetMacAge) GetCrcString() string {
	return "f58c37aa"
}
func NewBridgeDomainSetMacAge() api.Message {
	return &BridgeDomainSetMacAge{}
}

// BridgeDomainSetMacAgeReply represents the VPP binary API message 'bridge_domain_set_mac_age_reply'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 167:
//
//        ["bridge_domain_set_mac_age_reply",
//            ["u16", "_vl_msg_id"],
//            ["u32", "context"],
//            ["i32", "retval"],
//            {"crc" : "0xc127a682"}
//        ],
//
type BridgeDomainSetMacAgeReply struct {
	Retval int32
}

func (*BridgeDomainSetMacAgeReply) GetMessageName() string {
	return "bridge_domain_set_mac_age_reply"
}
func (*BridgeDomainSetMacAgeReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}
func (*BridgeDomainSetMacAgeReply) GetCrcString() string {
	return "c127a682"
}
func NewBridgeDomainSetMacAgeReply() api.Message {
	return &BridgeDomainSetMacAgeReply{}
}

// BridgeDomainAddDel represents the VPP binary API message 'bridge_domain_add_del'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 173:
//
//        ["bridge_domain_add_del",
//            ["u16", "_vl_msg_id"],
//            ["u32", "client_index"],
//            ["u32", "context"],
//            ["u32", "bd_id"],
//            ["u8", "flood"],
//            ["u8", "uu_flood"],
//            ["u8", "forward"],
//            ["u8", "learn"],
//            ["u8", "arp_term"],
//            ["u8", "mac_age"],
//            ["u8", "is_add"],
//            {"crc" : "0xbddc9ff1"}
//        ],
//
type BridgeDomainAddDel struct {
	BdID    uint32
	Flood   uint8
	UuFlood uint8
	Forward uint8
	Learn   uint8
	ArpTerm uint8
	MacAge  uint8
	IsAdd   uint8
}

func (*BridgeDomainAddDel) GetMessageName() string {
	return "bridge_domain_add_del"
}
func (*BridgeDomainAddDel) GetMessageType() api.MessageType {
	return api.RequestMessage
}
func (*BridgeDomainAddDel) GetCrcString() string {
	return "bddc9ff1"
}
func NewBridgeDomainAddDel() api.Message {
	return &BridgeDomainAddDel{}
}

// BridgeDomainAddDelReply represents the VPP binary API message 'bridge_domain_add_del_reply'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 187:
//
//        ["bridge_domain_add_del_reply",
//            ["u16", "_vl_msg_id"],
//            ["u32", "context"],
//            ["i32", "retval"],
//            {"crc" : "0xd5e138e4"}
//        ],
//
type BridgeDomainAddDelReply struct {
	Retval int32
}

func (*BridgeDomainAddDelReply) GetMessageName() string {
	return "bridge_domain_add_del_reply"
}
func (*BridgeDomainAddDelReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}
func (*BridgeDomainAddDelReply) GetCrcString() string {
	return "d5e138e4"
}
func NewBridgeDomainAddDelReply() api.Message {
	return &BridgeDomainAddDelReply{}
}

// BridgeDomainDump represents the VPP binary API message 'bridge_domain_dump'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 193:
//
//        ["bridge_domain_dump",
//            ["u16", "_vl_msg_id"],
//            ["u32", "client_index"],
//            ["u32", "context"],
//            ["u32", "bd_id"],
//            {"crc" : "0x68d5401d"}
//        ],
//
type BridgeDomainDump struct {
	BdID uint32
}

func (*BridgeDomainDump) GetMessageName() string {
	return "bridge_domain_dump"
}
func (*BridgeDomainDump) GetMessageType() api.MessageType {
	return api.RequestMessage
}
func (*BridgeDomainDump) GetCrcString() string {
	return "68d5401d"
}
func NewBridgeDomainDump() api.Message {
	return &BridgeDomainDump{}
}

// BridgeDomainDetails represents the VPP binary API message 'bridge_domain_details'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 200:
//
//        ["bridge_domain_details",
//            ["u16", "_vl_msg_id"],
//            ["u32", "context"],
//            ["u32", "bd_id"],
//            ["u8", "flood"],
//            ["u8", "uu_flood"],
//            ["u8", "forward"],
//            ["u8", "learn"],
//            ["u8", "arp_term"],
//            ["u8", "mac_age"],
//            ["u32", "bvi_sw_if_index"],
//            ["u32", "n_sw_ifs"],
//            ["vl_api_bridge_domain_sw_if_t", "sw_if_details", 0, "n_sw_ifs"],
//            {"crc" : "0x1840bc8b"}
//        ],
//
type BridgeDomainDetails struct {
	BdID         uint32
	Flood        uint8
	UuFlood      uint8
	Forward      uint8
	Learn        uint8
	ArpTerm      uint8
	MacAge       uint8
	BviSwIfIndex uint32
	NSwIfs       uint32 `struc:"sizeof=SwIfDetails"`
	SwIfDetails  []BridgeDomainSwIf
}

func (*BridgeDomainDetails) GetMessageName() string {
	return "bridge_domain_details"
}
func (*BridgeDomainDetails) GetMessageType() api.MessageType {
	return api.ReplyMessage
}
func (*BridgeDomainDetails) GetCrcString() string {
	return "1840bc8b"
}
func NewBridgeDomainDetails() api.Message {
	return &BridgeDomainDetails{}
}

// BridgeFlags represents the VPP binary API message 'bridge_flags'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 215:
//
//        ["bridge_flags",
//            ["u16", "_vl_msg_id"],
//            ["u32", "client_index"],
//            ["u32", "context"],
//            ["u32", "bd_id"],
//            ["u8", "is_set"],
//            ["u32", "feature_bitmap"],
//            {"crc" : "0xc1d50251"}
//        ],
//
type BridgeFlags struct {
	BdID          uint32
	IsSet         uint8
	FeatureBitmap uint32
}

func (*BridgeFlags) GetMessageName() string {
	return "bridge_flags"
}
func (*BridgeFlags) GetMessageType() api.MessageType {
	return api.RequestMessage
}
func (*BridgeFlags) GetCrcString() string {
	return "c1d50251"
}
func NewBridgeFlags() api.Message {
	return &BridgeFlags{}
}

// BridgeFlagsReply represents the VPP binary API message 'bridge_flags_reply'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 224:
//
//        ["bridge_flags_reply",
//            ["u16", "_vl_msg_id"],
//            ["u32", "context"],
//            ["i32", "retval"],
//            ["u32", "resulting_feature_bitmap"],
//            {"crc" : "0xfa6b7397"}
//        ],
//
type BridgeFlagsReply struct {
	Retval                 int32
	ResultingFeatureBitmap uint32
}

func (*BridgeFlagsReply) GetMessageName() string {
	return "bridge_flags_reply"
}
func (*BridgeFlagsReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}
func (*BridgeFlagsReply) GetCrcString() string {
	return "fa6b7397"
}
func NewBridgeFlagsReply() api.Message {
	return &BridgeFlagsReply{}
}

// L2InterfaceVlanTagRewrite represents the VPP binary API message 'l2_interface_vlan_tag_rewrite'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 231:
//
//        ["l2_interface_vlan_tag_rewrite",
//            ["u16", "_vl_msg_id"],
//            ["u32", "client_index"],
//            ["u32", "context"],
//            ["u32", "sw_if_index"],
//            ["u32", "vtr_op"],
//            ["u32", "push_dot1q"],
//            ["u32", "tag1"],
//            ["u32", "tag2"],
//            {"crc" : "0xb9dcbd39"}
//        ],
//
type L2InterfaceVlanTagRewrite struct {
	SwIfIndex uint32
	VtrOp     uint32
	PushDot1q uint32
	Tag1      uint32
	Tag2      uint32
}

func (*L2InterfaceVlanTagRewrite) GetMessageName() string {
	return "l2_interface_vlan_tag_rewrite"
}
func (*L2InterfaceVlanTagRewrite) GetMessageType() api.MessageType {
	return api.RequestMessage
}
func (*L2InterfaceVlanTagRewrite) GetCrcString() string {
	return "b9dcbd39"
}
func NewL2InterfaceVlanTagRewrite() api.Message {
	return &L2InterfaceVlanTagRewrite{}
}

// L2InterfaceVlanTagRewriteReply represents the VPP binary API message 'l2_interface_vlan_tag_rewrite_reply'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 242:
//
//        ["l2_interface_vlan_tag_rewrite_reply",
//            ["u16", "_vl_msg_id"],
//            ["u32", "context"],
//            ["i32", "retval"],
//            {"crc" : "0x901eddfb"}
//        ],
//
type L2InterfaceVlanTagRewriteReply struct {
	Retval int32
}

func (*L2InterfaceVlanTagRewriteReply) GetMessageName() string {
	return "l2_interface_vlan_tag_rewrite_reply"
}
func (*L2InterfaceVlanTagRewriteReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}
func (*L2InterfaceVlanTagRewriteReply) GetCrcString() string {
	return "901eddfb"
}
func NewL2InterfaceVlanTagRewriteReply() api.Message {
	return &L2InterfaceVlanTagRewriteReply{}
}

// L2InterfacePbbTagRewrite represents the VPP binary API message 'l2_interface_pbb_tag_rewrite'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 248:
//
//        ["l2_interface_pbb_tag_rewrite",
//            ["u16", "_vl_msg_id"],
//            ["u32", "client_index"],
//            ["u32", "context"],
//            ["u32", "sw_if_index"],
//            ["u32", "vtr_op"],
//            ["u16", "outer_tag"],
//            ["u8", "b_dmac", 6],
//            ["u8", "b_smac", 6],
//            ["u16", "b_vlanid"],
//            ["u32", "i_sid"],
//            {"crc" : "0xb7706c15"}
//        ],
//
type L2InterfacePbbTagRewrite struct {
	SwIfIndex uint32
	VtrOp     uint32
	OuterTag  uint16
	BDmac     []byte `struc:"[6]byte"`
	BSmac     []byte `struc:"[6]byte"`
	BVlanid   uint16
	ISid      uint32
}

func (*L2InterfacePbbTagRewrite) GetMessageName() string {
	return "l2_interface_pbb_tag_rewrite"
}
func (*L2InterfacePbbTagRewrite) GetMessageType() api.MessageType {
	return api.RequestMessage
}
func (*L2InterfacePbbTagRewrite) GetCrcString() string {
	return "b7706c15"
}
func NewL2InterfacePbbTagRewrite() api.Message {
	return &L2InterfacePbbTagRewrite{}
}

// L2InterfacePbbTagRewriteReply represents the VPP binary API message 'l2_interface_pbb_tag_rewrite_reply'.
// Generated from '/usr/share/vpp/api/l2.api.json', line 261:
//
//        ["l2_interface_pbb_tag_rewrite_reply",
//            ["u16", "_vl_msg_id"],
//            ["u32", "context"],
//            ["i32", "retval"],
//            {"crc" : "0x2d083312"}
//        ]
//
type L2InterfacePbbTagRewriteReply struct {
	Retval int32
}

func (*L2InterfacePbbTagRewriteReply) GetMessageName() string {
	return "l2_interface_pbb_tag_rewrite_reply"
}
func (*L2InterfacePbbTagRewriteReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}
func (*L2InterfacePbbTagRewriteReply) GetCrcString() string {
	return "2d083312"
}
func NewL2InterfacePbbTagRewriteReply() api.Message {
	return &L2InterfacePbbTagRewriteReply{}
}
