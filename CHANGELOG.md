# Changelog

Message updates and major project changes should be documented here.

## [Unreleased]

#### Changed

- L3VPN and BGP CT announcements whose label field is 0x000000 or 0x800000 now publish that label (0 or 524288) per RFC 8277 §2.2 instead of no label, so these routes get new hashes
- Labeled unicast (SAFI 4) follows RFC 8277 §2: announcements with label 0x800000 publish label 524288 (new hashes), withdrawals ignore the Compatibility field and publish no labels, one label with S=0 is published when the Multiple Labels Capability is not confirmed, IPv4 prefixes over 32 bits are dropped instead of capped, and the Path ID flag is only flipped on a failed parse while the table's ADD-PATH state is unknown
- ADD-PATH and Multiple Labels state is kept per monitored session (peer type, distinguisher and peer address; Loc-RIB: distinguisher and BGP ID) and per direction (RFC 7911 §5: Adj-RIB-In uses the peer's Send and router's Receive, Adj-RIB-Out the reverse), and SAFI 1/2, the NLRI and Withdrawn Routes fields and L3VPN/BGP CT drop NLRI that do not parse under a known state instead of retrying with the Path ID flag flipped (BGP-LS and MUP also read Path IDs by this state); library API: `PerPeerHeader.GetTableKey` is replaced by `SessionKey`, `bgp.UnmarshalMPReachNLRI`/`UnmarshalMPUnReachNLRI` drop the ADD-PATH map (set `PathIDs` instead), and `base.UnmarshalRoutes`, `unicast.UnmarshalUnicastNLRI` and `multicast.UnmarshalMulticastNLRI` take a `base.PathIDState`
- SAFI 1/2 and the NLRI and Withdrawn Routes fields drop NLRI with a prefix over 32 bits (IPv4) or 128 bits (IPv6) as malformed (RFC 4271 §4.3, RFC 7606 §5.3) instead of capping IPv4 lengths at 32; `base.UnmarshalRoutes`, `unicast.UnmarshalUnicastNLRI` and `multicast.UnmarshalMulticastNLRI` take an `ipv6` argument
- Post-policy Adj-RIB-In and pre-policy Adj-RIB-Out, whose ADD-PATH encoding no RFC fixes, decode with the negotiated Path ID setting first and the other on failure (rate-limited warning with router, peer and AFI/SAFI); a Loc-RIB's state lasts until the Peer Down of its last emulated peer and keeps the VRF/Table Names of all as an ordered set; route monitoring decodes with the session state at its place in the stream; an IPv4 peer and an IPv4-mapped IPv6 peer are separate sessions

#### Fixed

- Publish calls for the messages of one BMP connection are made in the order the messages arrive, so a withdraw is no longer handed to the publisher before its announce, nor a Peer Down before its peer's last routes. This orders the calls, not delivery: Kafka with sarama's defaults can still reorder on a retry, and peer and route messages go to different topics. At most 2×GOMAXPROCS (4 to 16) messages per connection are decoded at once, so a slow publisher holds up the router over TCP instead of growing goroutines without bound, and a panic decoding one message is logged and that message skipped instead of stopping the process. A Route Monitoring or Stats message that arrives before any Peer Up (which RFC 7854 §3.3 does not allow, but a dropped Peer Up causes) is published at once with the TCP source as its router, so a different router_hash, instead of waiting for the first Peer Up and taking its router: that wait leaked goroutines when no Peer Up came and would now stall the connection
- Closing a BMP connection, and stopping gobmp, publishes every message already read from it before the publisher is stopped, instead of dropping them or publishing to a stopped publisher
- gobmp stops gracefully on SIGTERM (docker/Kubernetes stop) as it does on SIGINT, publishing what it has read within 25 s or exiting with status 1; a second signal exits at once
- The Kafka publisher's Stop waits until the producer has delivered or failed every buffered message before closing, instead of dropping them on exit, and a publish after Stop returns an error instead of panicking
- The NATS publisher reconnects for as long as the server is away instead of giving up after 10 attempts and failing every later publish, and publishes to JetStream asynchronously, keeping the order of the publish calls, with at most 4096 messages awaiting acknowledgement (failures are logged, at most once a second); Stop waits up to 10 s for the acknowledgements and a publish after Stop returns an error

### 2026-03-01

#### Added

- SR Policy Type I segment support (IPv6 node address with SRv6 endpoint behavior) per RFC 9831 Section 2.4.9
- SR Policy Type J segment support (IPv6 link-local adjacency with SRv6 SID) per RFC 9831 Section 2.4.10
- SR Policy Type K segment support (IPv6 Local/Remote adjacency with SRv6 SID) per RFC 9831 Section 2.4.11
- BGP-LS SR Policy TLV types 1201–1205 wired to NLRI Get methods for structured segment list access

#### Fixed

- Error wrapping and silent suppression of non-nil errors across BMP parsing pipeline
- Append aliasing in MCAST-VPN test helpers causing slice corruption
- `os.Exit` in cmd binaries bypassing deferred cleanup including glog buffer flush
- Exhaustive `ProtoID` switch cases across 8 packages to eliminate unreachable default branches
- Exhaustive `SpecType` switch in FlowSpec `UnmarshalJSON` for complete type coverage
- `typeSwitchVar` and `singleCaseSwitch` gocritic findings in SR and BGP packages
- Unnecessary type conversions in `pkg/base` Label and Prefix Descriptor types
- Missing godot periods on exported comments throughout codebase
- Unsafe type assertions in FlowSpec JSON unmarshaling replaced with comma-ok checks
- Dead `done` channel removed from validator store
- Bounds validation restored in `makePrefixSpec` after unparam linter regression

### 2026-02-28

#### Added

- SR Policy Type H segment support (IPv6 Local/Remote adjacency) per RFC 9831 Section 2.4.8

#### Fixed

- BMP Stats Report TLV count validation against actual buffer size to prevent silent truncation
- Bounds checks in BMP Peer Up message parser to prevent panic on truncated messages

### 2026-02-27

#### Added

- SR Policy Type G segment support (IPv6 link-local adjacency) per RFC 9831 Section 2.4.7

#### Fixed

- Timestamp decoding in BMP messages

### 2026-02-25

#### Added

- SR Policy Type F segment support (IPv4 Local/Remote adjacency) per RFC 9256 Section 2.4.6
- RFC 9012 Tunnel Encapsulation Attribute parsing
- EVPN Type 7 Multicast Membership Report Synch route support per RFC 9251 Section 9.2
- EVPN Type 10 S-PMSI A-D route support per RFC 9572 Section 3.2

### 2026-02-23

#### Added

- EVPN Type 8 Multicast Leave Synch route parsing per RFC 9251 Section 9.3
- EVPN Type 11 Leaf A-D route parsing per RFC 9572 Section 3.3
- SR Policy Type E segment support per RFC 9256 Section 2.4.5

#### Fixed

- L3VPN CIDR rounding that corrupted prefix lengths (e.g. /30 → /32)

### 2026-02-18

#### Added

- SR Policy Type C segment support (IPv4 node address + index) per RFC 9256 Section 2.4.3
- EVPN Type 6 Selective Multicast Ethernet Tag (SMET) route parsing per RFC 9251 Section 9.1

### 2026-02-08

#### Added

- EVPN Type 9 Per-Region I-PMSI A-D route support per RFC 9572 Section 3.1

### 2026-02-03

#### Added

- SR Policy Type B segment support (SRv6 SID only) per RFC 9831 Section 2.4.2

### 2026-01-16

#### Added

- L2VPN EVPN support (AFI 25, SAFI 70) per RFC 7432 and RFC 8365
  - All 11 EVPN route types (Types 1–5 per RFC 7432, Types 6–11 per RFC 9251/9572)
  - MAC/IP Advertisement, Inclusive Multicast, Ethernet Segment, IP Prefix routes
  - 14 test functions covering all route types

### 2026-01-08

#### Added

- Route Target Constraint support for IPv4 (AFI 1, SAFI 132) per RFC 4684
- Route Target Constraint support for IPv6 (AFI 2, SAFI 132) per RFC 4684

### 2025-12-16

#### Added

- Route Target Constraint support for IPv4 (AFI 1, SAFI 132) per RFC 4684
- Route Target Constraint support for IPv6 (AFI 2, SAFI 132) per RFC 4684

- RFC 8669 support: BGP Prefix-SID path attribute
- BGP Prefix-SID Label-Index TLV (Type 1)
- BGP Prefix-SID Originator SRGB TLV (Type 3)
- Enables Segment Routing prefix SID distribution via BGP
- RFC 7311 support: AIGP (Accumulated IGP Metric) path attribute
- AIGP attribute parsing for IGP metric propagation across AS boundaries
- AIGP field in BaseAttributes for traffic engineering applications
- Enables IGP metric visibility in large service provider networks
- RFC 9723 support: BGP Colored Prefix Routing (CPR) for SRv6
- Color Extended Community extraction in IPv4 and IPv6 Unicast prefixes
- Color field in UnicastPrefix message type for intent-aware routing
- RFC 5701 support: IPv6 Address Specific Extended Community
- IPv6-based Route Target and Route Origin extended communities
- Type 0x05 Extended Community parsing
- Enables IPv6 VPN route target filtering
- RFC 8097 support: BGP Prefix Origin Validation State Extended Community
- RPKI origin validation state extraction in Unicast and L3VPN prefixes
- Origin validation state field in UnicastPrefix and L3VPNPrefix message types
- Enables RPKI route validation monitoring and security analysis
- MCAST-VPN support for IPv4 (AFI 1, SAFI 5) per RFC 6514
- MCAST-VPN support for IPv6 (AFI 2, SAFI 5) per RFC 6514
- Support for all 7 MCAST-VPN route types: Intra-AS I-PMSI A-D, Inter-AS I-PMSI A-D, S-PMSI A-D, Leaf A-D, Source Active A-D, Shared Tree Join, Source Tree Join
- MVPN support for IPv4 (AFI 1, SAFI 129) per RFC 6514
- MVPN support for IPv6 (AFI 2, SAFI 129) per RFC 6514
- Support for all 7 MVPN route types (reusing MCAST-VPN parser): Intra-AS I-PMSI A-D, Inter-AS I-PMSI A-D, S-PMSI A-D, Leaf A-D, Source Active A-D, Shared Tree Join, Source Tree Join

### 2025-12-15

#### Added

- IPv4 Multicast support (AFI 1, SAFI 2) per RFC 4760
- IPv6 Multicast support (AFI 2, SAFI 2) per RFC 4760
- **VPLS Support (AFI 25, SAFI 65):** RFC 4761, RFC 6074, RFC 7854, RFC 4360 compliant
  - **RFC 4761** (VPLS-BGP): 17-byte NLRI format with VE ID and MPLS label blocks
  - **RFC 6074** (BGP-AD): 12-byte NLRI format with PE IPv4 address
  - **RFC 7854** (BMP): BMP protocol integration with error handling
  - **RFC 4360** (Extended Communities): Layer2 Info and Route Target parsing

  **NLRI Parsing:**
  - Length-based demultiplexing (12 vs 17 bytes)
  - MPLS label block calculation for RFC 4761
  - Both RFC formats supported in single BGP session

  **Extended Communities:**
  - Layer2 Info (Type 0x800A): Encapsulation type, control flags, MTU
  - Route Target (Types 0x0002, 0x0102, 0x0202): 3 RT format types
  - 19 encapsulation types (Ethernet, VLAN, ATM, Frame Relay, etc.)

  **Implementation:**
  - New package: `pkg/vpls/` with 9 test functions, 48 sub-tests
  - Performance benchmarks: 8 functions, <200 ns/op per operation
  - Message structure: `VPLSPrefix` in `pkg/message/types.go`
  - Kafka topic: `gobmp.parsed.vpls` (topic ID 17)

  **Test Results:**
  - 13 test functions, 52 tests
  - RFC 4761 parsing: 93.86 ns/op, 160 B/op
  - RFC 6074 parsing: 96.37 ns/op, 176 B/op
  - Route Target parsing: 12.73 ns/op, 32 B/op

### 2023-04-13

#### Changed

- SR value "prefix_sid" was previous configured with "omitempty" json tag option, this option is now removed. A valid
  SID index of 0 is now explicit in the json output.

### 2023-03-20

#### Fixed

- unresv\_bw\_kbps data structure was appending a slice, leaving initial 0 values and growing beyond the expected length.
  Updated function to index the slice to overwrite initial values and keep the expected length.
  [\#215](https://github.com/sbezverk/gobmp/issues/215)

### 2023-02-23

#### Added

- ls\_link attribute max\_link\_bw\_kbps BGP-LS TLV Type 1089 stored as an uint64 integer in kbps
  [\#213](https://github.com/sbezverk/gobmp/issues/213)
- ls\_link attribute max\_resv\_bw\_kbps BGP-LS TLV Type 1090 stored as uint64 integer in kbps
  [\#213](https://github.com/sbezverk/gobmp/issues/213)
- ls\_link attribute unresv\_bw\_kbps BGP-LS TLV Type 1091 stored as a slice of 8 uint64 integers in kbps
  [\#213](https://github.com/sbezverk/gobmp/issues/213)

#### Deprecated

- ls\_link attribute max\_link\_bw BGP-LS TLV Type 1089 statically set to 0
  [\#213](https://github.com/sbezverk/gobmp/issues/213)
- ls\_link attribute max\_resv\_bw BGP-LS TLV Type 1090 statically set to 0
  [\#213](https://github.com/sbezverk/gobmp/issues/213)
- ls\_link attribute unresv\_bw BGP-LS TLV Type 1091 statically set to nil
  [\#213](https://github.com/sbezverk/gobmp/issues/213)
