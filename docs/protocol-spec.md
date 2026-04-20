# Aether Wire Protocol — Wire Specification v6.1

> **v6.1 changes from v6.0:**
> - **§15 Version Negotiation REMOVED** — no pre-handshake negotiation; Aether is the only wire protocol. Identity comes from transport crypto.
> - **ECN complete** (§9.3) — IP_RECVTOS / IPV6_RECVTCLASS cmsg plumbing shipped for Linux/Darwin/BSD + Winsock IP_RECVECN for Windows + js/wasm stub.
> - **0.5-RTT session resume complete** (§31) — wire protocol for cross-host ticket delivery via `HandshakeResumeMaterial` HANDSHAKE frame, initiator cache, replay guard, AEAD proof tags, accept/reject prefixes (0xFA/0xF8/0xF9).
> - **NAT RFC 5780 wired end-to-end** (§14) — `Runtime.NATBehaviour()` / `NATStrategy()` / `PickTraversalMethod(remote)` exposed; Strategy engine orchestrates direct / hole-punch / UPnP / relay per peer classification.
> - **Multipath L3 WDRR shipped** (§30.3) — weighted-deficit round-robin formula corrected (argmin of bytes-scheduled/weight); gossip RTT feeds `RecordPathStats`; Level 2 + Level 3 enabled by default per peer.
> - **S1-S9 security remediation complete** — retry token on by default, per-source IP rate limit with LRU eviction, composite ACK scans bounded, FEC decoder count + age pruning, migration HMAC with replay guard, stream-count admission cap with RESET(Refused), abuse scoring with circuit breaker (5 call sites), SeqNo wrap detection, relay scope WFQ with cross-scope preemption.
> - **Runtime-mutable toggles** — `aether.CompressionCapable` / `AbuseScoreCapable` / `IdleEvictable` agnostic interfaces let consumers tune sessions without adapter-specific imports.
> - **Unified constructors** — every adapter now takes `SessionOptions` end-to-end via `NewSessionForProtocol(conn, proto, local, remote, opts) (Session, Protocol, error)`; `NormalizeSessionOptions` applies numeric defaults for zero-values.
> - **Post-remediation hardening** — compression-bomb guard, short-header `Frame.Validate()` gate, fragment buffer caps, AckDelay lower bound, `FlagANTIREPLAY` unconditional on DATA, atomic congestion-controller swap, `SessionIdleTimeout` eviction.
>
> **v6.0 changes from v5.1:** All code identifiers renamed from HWP to Aether. Reed-Solomon FEC added. BBRv2 rewritten with delivery rate sampling + round counting + 4-phase state machine. ECN signal integration (`OnCE()`). NAT RFC 5780. Send-time pacer for BBRv2. Reliability split send/recv mutexes. RetransmitQueue O(log N) removal via indexed heap. Adapter decomposed into 4 files (was 5 in plan, helpers folded). Fragment buffer keyed per-stream. Inbox channel configurable with drop counter. FEC decoder deterministic min-groupID eviction.
>
> **Module:** `github.com/ORBTR/aether`
> **Status:** Specification (v6.1)
> **Date:** 2026-04-18
> **Authors:** HSTLES / ORBTR Pty Ltd

## Terminology

- **Aether** is both the package name (`github.com/ORBTR/aether`) and the wire format name.
- All code identifiers, error prefixes, and debug loggers use the `aether` namespace.

## Overview

The Aether Wire Protocol is the canonical internal frame format carried by ALL mesh transports. Every UDP packet, TCP stream, WebSocket message, QUIC stream, and gRPC call carries Aether frames. The transport is just a pipe — Aether is the language.

An Aether stream is a virtual wire — indistinguishable from a TCP connection to the application layer. Callers use standard Go `io.Reader`/`io.Writer`/`net.Conn` interfaces. Aether handles multiplexing, reliability, flow control, congestion, encryption, and MTU fragmentation transparently.

Aether provides: stream multiplexing, reliability (retransmission + Composite ACK), congestion control (CUBIC/BBR), forward error correction (FEC), credit-based flow control, weighted fair queuing (WFQ) priority scheduling, per-frame AEAD encryption, sender/receiver identity routing, anti-replay protection, NAT traversal signaling, inline configuration push, MTU-aware fragmentation, and a `net.Conn` virtual wire interface.

Transports with native capabilities (QUIC, TCP) skip the redundant Aether layers. Transports without (Noise-UDP) activate the full Aether stack.

---

## 1. Frame Format

### 1.1 Header Layout (50 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         SenderID (8 bytes)                    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        ReceiverID (8 bytes)                   |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         StreamID (8 bytes)                    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Flags     |         SeqNo (4 bytes)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   SeqNo cont  |             AckNo (4 bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| AckNo cont    |            Length (4 bytes)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Length cont  |              Nonce (12 bytes)                  |
+-+-+-+-+-+-+-+-+                                               |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Payload (variable)                     |
|                            ...                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 1.2 Field Definitions

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | SenderID | Truncated SHA-256[:8] fingerprint of sender's Ed25519 public key. Identifies the originating node. |
| 8 | 8 | ReceiverID | Truncated fingerprint of intended receiver. `0x0000000000000000` = broadcast (gossip). Enables relay routing without decrypting payload. |
| 16 | 8 | StreamID | Consumer-defined logical stream identifier. Consumers assign stream IDs via `StreamLayout` (see section 4). `0xFFFFFFFFFFFFFFFF` = connection-level flow control sentinel. |
| 24 | 1 | Type | Frame type enum (see section 2). |
| 25 | 1 | Flags | Bitfield (see section 3). |
| 26 | 4 | SeqNo | Per-stream sender sequence number. Used for ordering, reliability (Composite ACK), and anti-replay (when ANTIREPLAY flag set). Monotonically increasing per stream. Control frames (WINDOW, ACK, PING, PONG, GOAWAY, CLOSE, RESET, PRIORITY) set SeqNo=0. |
| 30 | 4 | AckNo | Piggyback acknowledgment. Highest contiguous SeqNo received from peer on this stream. Reduces ACK-only frames. |
| 34 | 4 | Length | Payload length in bytes. Maximum 16,777,216 (16 MB). Zero for control frames with no payload (PING, PONG). |
| 38 | 12 | Nonce | AEAD nonce for ChaCha20-Poly1305 encryption. Zero when ENCRYPTED flag is not set. Counter-based for ordered streams, random for unordered. |
| 50 | var | Payload | Application data or typed control payload. Encrypted if ENCRYPTED flag set. Compressed if COMPRESSED flag set. Maximum `Length` bytes. |

### 1.3 Byte Order

All multi-byte fields are **big-endian** (network byte order).

### 1.4 Maximum Frame Size

- Header: 50 bytes (fixed)
- Payload: 0 to 16,777,216 bytes
- Maximum total frame: 16,777,266 bytes
- AEAD overhead: 16 bytes (Poly1305 auth tag, included in Length when ENCRYPTED)

---

## 2. Frame Types

### 2.1 Data Plane

| Code | Name | Payload | Description |
|------|------|---------|-------------|
| 0x01 | DATA | Application data | Primary data transport. May carry SYN flag for zero-RTT stream open. |
| 0x0C | FEC_REPAIR | `[GroupID:4][Index:1][Total:1][XOR_payload:var]` | Forward error correction repair packet. XOR of all data frames in the group. Enables single-frame recovery without retransmission. |

### 2.2 Stream Lifecycle

| Code | Name | Payload | Description |
|------|------|---------|-------------|
| 0x02 | OPEN | `[Reliability:1][Priority:1][Dependency:8]` | Opens a new stream with specified QoS parameters. |
| 0x03 | CLOSE | (empty) | Graceful stream close (FIN). Sender will send no more data. Receiver continues until its own CLOSE. |
| 0x04 | RESET | `[ReasonCode:4]` | Immediate stream abort. Both sides receive error on next Send/Receive. Reason codes: Cancel(0), Refused(1), Internal(2), FlowCtrl(3), Timeout(4). |

### 2.3 Reliability

| Code | Name | Payload | Description |
|------|------|---------|-------------|
| 0x08 | ACK | Composite ACK (see section 2.8) | Bitmap-based acknowledgment with adaptive frequency. AckNo in header = cumulative ACK (BaseACK). FlagCOMPOSITE_ACK (0x80) set on all ACK frames. |

### 2.4 Flow Control

| Code | Name | Payload | Description |
|------|------|---------|-------------|
| 0x05 | WINDOW | `[Credit:4]` | Grants additional flow control credit (bytes). StreamID=0xFFFFFFFFFFFFFFFF for connection-level. |
| 0x0A | PRIORITY | `[Weight:1][Dependency:8]` | Changes stream scheduling weight (1-255) and dependency parent. |

### 2.5 Connection Health

| Code | Name | Payload | Description |
|------|------|---------|-------------|
| 0x06 | PING | (empty) | Keepalive / RTT measurement. SeqNo used as ping identifier. |
| 0x07 | PONG | (empty) | Keepalive response. Echoes the PING's SeqNo for RTT calculation. |
| 0x0B | GOAWAY | `[Reason:4][Message:var]` | Graceful connection shutdown. No new streams after GOAWAY. Existing streams drain. Reason: Normal(0), Error(1), Migration(2), Overload(3). |

### 2.6 Control Plane

| Code | Name | Payload | Description |
|------|------|---------|-------------|
| 0x0D | WHOIS | `[TargetPeerID:8][ResponseFlag:1][NodeID_len:2][NodeID:var][PubKey:32]` | Fast identity resolution. Request has ResponseFlag=0 and only TargetPeerID. Response has ResponseFlag=1 with full NodeID and Ed25519 public key. Sub-100ms resolution vs 10-30s gossip. |
| 0x0E | RENDEZVOUS | `[TargetPeerID:8][ObservedIP:16][ObservedPort:2][NATType:1]` | NAT traversal hints. A relay node sends this to both peers with each other's observed addresses for simultaneous UDP hole-punching. ObservedIP is IPv6-mapped (16 bytes, IPv4 uses ::ffff:x.x.x.x). NATType: Unknown(0), Open(1), FullCone(2), Restricted(3), PortRestricted(4), Symmetric(5), Blocked(6). |
| 0x0F | NETWORK_CONFIG | `[ConfigType:1][Version:4][Signature:64][ConfigData:var]` | Inline signed configuration push. ConfigType: Policy(0), Roles(1), NetworkKeys(2), Revocation(3). Signature is Ed25519 over `[ConfigType][Version][ConfigData]` by tenant root or platform root key. Enables instant config propagation without C2 HTTP round-trip. |
| 0x10 | HANDSHAKE | `[HandshakeType:1][Payload:var]` | In-band session renegotiation. HandshakeType: KeyRotation(0), CapabilityUpdate(1), SessionResume(2), AddressMigration(3), ResumeMaterial(4). See §21 for AddressMigration payload (74 bytes), §31.8 for ResumeMaterial payload format. |

### 2.7 Observability

| Code | Name | Payload | Description |
|------|------|---------|-------------|
| 0x11 | STATS | `[RTT_us:4][Loss_ppm:4][CWND:4][Retransmits:4][FramesSent:8][BytesSent:8][ActiveStreams:2]` | Periodic session stats report (34 bytes). Sent every 30s on control stream. |
| 0x12 | TRACE | `[TraceID:8][HopIndex:1][NodeID:8][Timestamp:8][Latency_us:4]` | Distributed RPC trace. Each hop appends its entry (29 bytes). |
| 0x13 | PATH_PROBE | `[ProbeID:4][PayloadSize:2][Padding:var]` | Active path measurement + PMTU discovery. Response echoes ProbeID. |

### 2.8 Composite ACK

Unified bitmap-based acknowledgment format used by all ACK frames.

#### ACK-LITE (8 bytes — no gaps detected)
```
[BaseACK:4][AckDelay:2][BitmapLen:1=0][Flags:1]
```

#### ACK-FULL (12+ bytes — gaps exist)
```
[BaseACK:4][AckDelay:2][BitmapLen:1][Bitmap:N][Flags:1][extensions...]
```

#### Fields
| Field | Size | Description |
|-------|------|-------------|
| BaseACK | 4 | Highest contiguous SeqNo received (cumulative ACK) |
| AckDelay | 2 | Receiver processing delay in 8us units (max ~524ms). Used for RTT measurement: adjustedRTT = max(rawRTT - AckDelay*8us, 1us) |
| BitmapLen | 1 | Bitmap length in bytes (0/4/8/16/32 = 0/32/64/128/256 bits). 0 = ACK-lite (pure cumulative) |
| Bitmap | N | Forward window bitmap. Bit i=1 means BaseACK+1+i received. ONLY represents the forward window. |
| Flags | 1 | Extension flags (see below) |

#### Extension Flags (CompositeACKFlags)
| Bit | Name | Description |
|-----|------|-------------|
| 0x01 | HasExtRanges | Extended SACK ranges follow (max 8, for beyond bitmap window) |
| 0x02 | HasDropped | Dropped ranges follow (max 4, sorted, non-overlapping, merged). Tells sender to stop retransmitting. |
| 0x04 | HasLossDensity | 2-byte advisory loss rate follows. (missed/256)*10000 over last 256 packets. |
| 0x10 | InvertedBitmap | Reserved for future use. bit=1 means MISSING instead of received. |
| 0x20 | HasGaps | Receive window has gaps. MUST be set if any gap exists. ACK-lite (BitmapLen=0) is ONLY valid when HasGaps=0. |

#### Optional Extensions (in order, only if flagged)
```
[ExtRangeCount:1][Start:4 End:4]... — SACK ranges beyond bitmap window
[DroppedCount:1][Start:4 End:4]...  — Ranges receiver dropped (never retransmit)
[LossRate:2]                        — Advisory loss density
```

#### Adaptive ACK Frequency
ACKs are not sent after every packet. The ACK engine uses:
- ACK every 2 packets OR every 25ms (whichever first)
- Immediate ACK on gap detection (out-of-order frame)
- Immediate ACK on control stream frames
- Immediate ACK on first packet after idle (> 1xSRTT)
- Flush ACK on stream close

#### Loss Detection (Sender Side)
1. Cumulative ACK: remove all entries <= BaseACK
2. Bitmap: bit=1 -> ACK, bit=0 -> implicit NACK candidate
3. Fast retransmit only if (largestAcked - missingSeqNo) >= 3 (reorder threshold)
4. Extended ranges: ACK all in range
5. Dropped ranges: permanently remove (scope validated to (BaseACK, largestSent])
6. Stall detection: no progress for 2xSRTT -> probe retransmit oldest unacked

---

## 3. Flags

| Bit | Name | Description |
|-----|------|-------------|
| 0x01 | FIN | Last frame in stream. After FIN, sender will send no more DATA on this stream. |
| 0x02 | SYN | Stream open. When set on a DATA frame, implicitly opens the stream (zero-RTT, no separate OPEN frame needed). |
| 0x04 | ACK | Acknowledgment piggyback. AckNo field is meaningful (cumulative ACK for peer's data). Reduces standalone ACK frames. |
| 0x08 | PRIORITY | Priority field present in payload (for DATA frames carrying inline priority hints). |
| 0x10 | ENCRYPTED | Payload is encrypted with ChaCha20-Poly1305. Nonce field is meaningful. Header bytes 0-37 are AEAD additional data (authenticated but not encrypted). |
| 0x20 | COMPRESSED | Payload is DEFLATE compressed. Applied before encryption (compress then encrypt). |
| 0x40 | ANTIREPLAY | SeqNo serves as anti-replay counter. **Only applies to DATA frames (TypeDATA).** Control frames (WINDOW, ACK, PING, PONG, GOAWAY, CLOSE, RESET, PRIORITY) have SeqNo=0 and bypass anti-replay checking entirely. Receiver maintains a 64-packet sliding window and silently drops DATA frames with duplicate or out-of-window SeqNo. Per-stream scope. |
| 0x80 | COMPOSITE_ACK | Payload uses Composite ACK format (bitmap + extensions). Set on all TypeACK frames. |

There is no ECN flag. ECN signaling is carried inline in the Composite ACK extensions via the HasLossDensity flag (see section 2.8).

---

## 4. Streams

Stream IDs are **consumer-defined**. The protocol does not mandate fixed stream IDs for gossip, RPC, or any application function. Consumers assign stream IDs when creating sessions via the `StreamLayout` struct.

### 4.1 Protocol-Reserved Streams

The protocol reserves only two stream functions in `StreamLayout`:

| Field | Purpose | Default ID | Description |
|-------|---------|------------|-------------|
| Keepalive | Liveness detection | 2 | Stream for PING/PONG health probes. 0 = disabled. |
| Control | Control plane | 3 | Stream for GOAWAY, HANDSHAKE, WHOIS, RENDEZVOUS, NETWORK_CONFIG, STATS, TRACE. 0 = disabled. |

The `DefaultStreamLayout()` returns Keepalive=2, Control=3. Consumers override these as needed.

### 4.2 Connection-Level Sentinel

`StreamID = 0xFFFFFFFFFFFFFFFF` is a sentinel for connection-level WINDOW frames. It is not a real stream.

### 4.3 Consumer Stream Assignment

All application streams (gossip, RPC, tunnels, file transfer, telemetry, etc.) are assigned by the consumer. The protocol does not constrain their IDs or ordering. `MaxStreamID = 2^62 - 1` — when exhausted, send GOAWAY and create a new session.

### 4.4 Example Consumer Layout (ORBTR Agent)

| StreamID Range | Name | Reliability | Priority | Latency Class | MaxAge |
|----------------|------|-------------|----------|---------------|--------|
| 0 | Gossip | BestEffort | 64 | BULK | — |
| 1 | RPC | ReliableOrdered | 128 | INTERACTIVE | — |
| 2 | Keepalive | UnreliableSequenced | 255 | REALTIME | — |
| 3 | Control | ReliableOrdered | 240 | REALTIME | — |
| 100 | Screen key frames | ReliableOrdered | 200 | INTERACTIVE | — |
| 101 | Screen delta frames | UnreliableSequenced | 128 | BULK | 100ms |
| 102 | Input events (mouse/keyboard) | ReliableOrdered | 255 | REALTIME | 50ms |
| 200+ | Tunnels (RDP/SSH/VNC) | ReliableOrdered | 192 | INTERACTIVE | — |
| 300+ | File transfer | ReliableOrdered | 160 | BULK | — |
| 400 | Telemetry | BestEffort | 32 | BULK | 10s |
| 401 | Heartbeat | ReliableOrdered | 224 | INTERACTIVE | — |
| 500 | Emergency policy | ReliableOrdered | 255 | REALTIME | — |
| 501 | Normal policy | ReliableOrdered | 176 | INTERACTIVE | — |
| 600-699 | File transfer (bulk) | ReliableUnordered | 160 | BULK | — |

This layout is consumer-defined, not protocol-mandated.

---

## 5. Reliability Modes

Each stream is opened with one of five reliability modes, specified in the OPEN frame payload.

| Mode | Value | Retransmit | Ordering | Drop Policy | Use Case |
|------|-------|------------|----------|-------------|----------|
| ReliableOrdered | 0 | Yes (unlimited) | Strict in-order | Never drop | RPC, file transfer, tunnels, policy |
| ReliableUnordered | 1 | Yes (unlimited) | Any order | Never drop | Bulk data, parallel chunks |
| UnreliableOrdered | 2 | No | Strict in-order | Drop stale (older than newest delivered) | Telemetry, metrics |
| UnreliableSequenced | 3 | No | Latest-wins | Drop all older than newest received | Screen deltas, heartbeat, status |
| BestEffort | 4 | Yes (limited by MaxRetries/MaxAge) | In-order attempt | Drop after retry budget | Gossip deltas (convergent) |

### 5.1 BestEffort Parameters

BestEffort mode accepts additional parameters in the OPEN payload:

| Field | Size | Description |
|-------|------|-------------|
| MaxRetries | 1 byte | Maximum retransmission attempts (0=default 3) |
| MaxAge | 4 bytes | Maximum frame age in milliseconds before drop (0=default 10s) |

---

## 6. Encryption

### 6.1 Algorithm

**ChaCha20-Poly1305** (RFC 8439) — authenticated encryption with associated data (AEAD).

- Key size: 256 bits (32 bytes)
- Nonce size: 96 bits (12 bytes)
- Auth tag size: 128 bits (16 bytes, appended to ciphertext)

### 6.2 Key Derivation

Session keys are derived from the transport handshake shared secret via HKDF-SHA256. Three separate keys are derived with distinct info strings, ensuring cryptographic separation.

```
PRK = HKDF-Extract(salt=nil, IKM=sharedSecret)

EncryptionKey = HKDF-Expand(PRK, info="aether-enc-v1"  || localID || remoteID, L=32)
AuthKey       = HKDF-Expand(PRK, info="aether-auth-v1" || localID || remoteID, L=32)
IVKey         = HKDF-Expand(PRK, info="aether-iv-v1"   || localID || remoteID, L=32)
```

- **Salt:** nil (HKDF uses a zero-length salt internally)
- **IKM:** shared secret from Noise handshake output (minimum 32 bytes)
- **Info strings:** `"aether-enc-v1"`, `"aether-auth-v1"`, `"aether-iv-v1"` — each prefixed with the concatenation of localID and remoteID strings to bind keys to the specific session
- **EncryptionKey:** ChaCha20-Poly1305 AEAD key for per-frame encryption
- **AuthKey:** HMAC key for migration tokens and resume token validation
- **IVKey:** Additional entropy for nonce generation

Implementation: `crypto/keyring.go:DeriveKeyring()`

### 6.3 Nonce Generation

- **Ordered streams:** Counter-based. 4 zero bytes + 8-byte big-endian counter. Monotonically increasing. Counter MUST NOT repeat for the same key.
- **Unordered streams:** Random nonce via crypto/rand for replay safety under concurrent sends.

### 6.4 Additional Data

AEAD additional data = header bytes 0-37 (everything before the Nonce field). This authenticates:
- SenderID, ReceiverID (for routing verification)
- StreamID, Type, Flags (for frame integrity)
- SeqNo, AckNo (for ordering/reliability integrity)
- Length (for payload boundary integrity)

The header is NOT encrypted — relay nodes can inspect SenderID/ReceiverID for routing without access to the session key.

### 6.5 When Encryption Is Used

| Transport | ENCRYPTED Flag | Reason |
|-----------|---------------|--------|
| Noise-UDP | OFF | Noise provides encryption at transport layer |
| QUIC | OFF | TLS 1.3 provides encryption |
| TLS/TCP | OFF | TLS provides encryption |
| WebSocket over TLS | OFF | TLS provides encryption |
| WebSocket over plain HTTP | **ON** | No transport encryption |
| gRPC without TLS | **ON** | No transport encryption |
| Relay forwarding | **ON** | Relay must not read payload (end-to-end encryption) |

---

## 7. Anti-Replay Protection

### 7.1 Per-Stream Replay Window (64-bit)

When `FlagANTIREPLAY` (0x40) is set:

1. The SeqNo field serves as a monotonically increasing counter.
2. The receiver maintains a **64-packet sliding window** per stream using a `uint64` bitmap.
3. Frames are accepted if:
   - SeqNo > window_top: advance window, accept
   - window_top - 63 <= SeqNo <= window_top: check bitmap, accept if not seen, mark as seen
   - SeqNo < window_top - 63: reject (too old)
4. Duplicate or out-of-window frames are dropped silently (no error response).

Anti-replay is per-stream. Each stream has its own replay window. This prevents cross-stream replay attacks where a frame from stream A is replayed on stream B.

Implementation: `reliability/antireplay.go:ReplayWindow`

### 7.2 Per-Connection Replay Window (128-bit)

A 128-bit packet-level replay window operates per connection, BEFORE stream demultiplexing. This catches replayed encrypted UDP packets at the transport layer, separate from the per-stream SeqNo replay window.

- **Window size:** 128 packets
- **Bitmap:** `[2]uint64` (two 64-bit words)
- **Sequence type:** `uint64` (packet sequence, not stream SeqNo)
- **Scope:** Connection-level (all streams combined)
- **DATA frames only:** Control frames (WINDOW, ACK, PING, PONG, GOAWAY, CLOSE, RESET, PRIORITY) have SeqNo=0 and are exempt from replay checking. Applying anti-replay to control frames caused WINDOW_UPDATE frames to be silently dropped after the first one (SeqNo=0 seen as duplicate), permanently draining flow control credit and stalling streams.

Implementation: `reliability/packet_replay.go:PacketReplayWindow`

---

## 8. Flow Control

### 8.1 Stream-Level

- **Initial credit:** 262,144 bytes (256 KB)
- **Maximum credit:** 262,144 bytes (256 KB) per stream
- **Auto-grant threshold:** 25% consumed (64 KB) — receiver sends WINDOW after consuming 25% of the initial credit, ensuring credit is replenished after every exchange
- **Configurable credit:** `StreamConfig.InitialCredit` allows per-stream credit override. File transfer streams use 2 MB; gossip/RPC use the default 256 KB. When set, `DefaultMaxStreamCredit` is raised to match.
- **Consume() blocking:** `Consume()` blocks up to 10 seconds polling for WINDOW_UPDATE instead of failing immediately on insufficient credit
- **MinGuaranteedWindow:** 1 KB — small frames (headers, control messages) always pass even when credit is near zero, preventing deadlock when the window floors at zero
- **Backpressure:** Sender blocks on `Stream.Send()` when credit exhausted. Unblocks on WINDOW frame receipt.
- **Signal:** WINDOW frame (Type 0x05) with `[Credit:4]` payload, StreamID = target stream.
- **DeliverToRecvCh:** Uses adaptive backpressure (100ms-200ms timeout). When recvCh is full, the frame is dropped but `ReceiverConsume()` is always called to return flow control credit. This prevents permanent credit drain when a slow consumer causes channel overflow.
- **Credit-on-drop:** When a frame is dropped due to full recvCh, the receiver still calls `ReceiverConsume(frameLen)` to return credit to the sender via WINDOW. Without this, dropped frames permanently reduce the available window.

Implementation: `flow/stream_window.go`

### 8.2 Connection-Level

- **Initial credit:** 1,048,576 bytes (1 MB)
- **Maximum credit:** 16,777,216 bytes (16 MB)
- **Auto-grant threshold:** 25% consumed
- **Signal:** WINDOW frame with StreamID = `0xFFFFFFFFFFFFFFFF`
- **Purpose:** Prevents any single stream from starving the connection. All stream sends also consume connection credit.

---

## 9. Congestion Control

Active only on transports without native congestion control (Noise-UDP). QUIC, TCP, and gRPC transports skip this entirely.

### 9.1 CUBIC (Default)

RFC 8312 implementation:

- **Slow start:** cwnd doubles per RTT until ssthresh or loss
- **Congestion avoidance:** CUBIC function `W(t) = C * (t - K)^3 + W_max`
- **Fast recovery:** cwnd = ssthresh = 0.7 * cwnd_at_loss
- **Constants:** C=0.4, beta=0.7
- **Initial cwnd:** 14,000 bytes (10 x 1400 MSS)
- **Minimum cwnd:** 2,800 bytes (2 x MSS)
- **Maximum cwnd:** 10,485,760 bytes (10 MB)
- **Scope:** Per-connection (all streams share one congestion window)

### 9.2 BBRv2

Full BBRv2 implementation (configurable per-session via `SessionOptions.CongestionAlgo`):

- **Delivery rate sampling:** Per-packet `DeliveryRateSample` stored in SendWindow entries. Tracks bytes delivered at send time and ACK time to compute instantaneous delivery rate.
- **Round counting:** `RoundCounter` tracks delivered bytes at round start. A round completes when the ACK acknowledges a packet sent after the round began.
- **Inflight tracking:** `inflightBytes` incremented on send, decremented on ACK. Used for BDP computation.
- **State machine:**
  - **Startup** (gain=2.89): Exit after 3 consecutive rounds without BtlBW increase
  - **Drain** (gain=0.35): Exit when inflight ≤ BDP
  - **ProbeBW** (8-phase gain cycle): Cycles through gain factors [1.25, 0.75, 1, 1, 1, 1, 1, 1] with per-phase timing
  - **ProbeRTT**: Triggered at 10s min-RTT expiry, reduces cwnd to 4 packets for 200ms
- **CWND computation:** `BDP × gain_factor` where BDP = `BtlBW × min_RTT`
- **Loss response:** 15% cwnd reduction per loss event (gentler than CUBIC's 30%)
- **Pacing:** Uses send-time scheduling (not token bucket) for precise inter-packet spacing
- **Bottleneck bandwidth:** Windowed max-filter over 10 delivery rate samples
- **Min RTT:** Tracked with 10s expiry, triggering ProbeRTT for refresh

### 9.3 ECN (Explicit Congestion Notification)

Aether implements RFC 3168 ECN receive-side signal integration across all native platforms. Kernel-level plumbing shipped in v6.1.

**Receive-side cmsg plumbing** (`noise/socket_ecn_{unix,windows,js}.go`):

| Platform | Socket option | Cmsg layout |
|----------|---------------|-------------|
| Linux / Darwin / FreeBSD / NetBSD / OpenBSD | `IP_RECVTOS` (IPv4), `IPV6_RECVTCLASS` (IPv6) via `golang.org/x/sys/unix.SetsockoptInt` | `unix.ParseSocketControlMessage` → match `IPPROTO_IP/IP_TOS` or `IPPROTO_IPV6/IPV6_TCLASS` |
| Windows | `IP_RECVECN` (option 50 on `IPPROTO_IP`), `IPV6_RECVECN` (option 50 on `IPPROTO_IPV6`) via Winsock | `WSAMSG` cmsg parsed manually — Windows delivers the ECN codepoint (0-3) directly, not the full TOS byte |
| js/wasm | No-op stub — no raw UDP available in the browser |

The ECN codepoint lives in the bottom two bits of the TOS / traffic-class byte (RFC 3168):

| Codepoint | Meaning |
|-----------|---------|
| 0b00 | Not-ECT — non-ECN-capable traffic |
| 0b01 | ECT(1) |
| 0b10 | ECT(0) |
| 0b11 | CE — **congestion experienced** |

**Signal path:**

1. Kernel delivers `IP_TOS` / `IPV6_TCLASS` cmsg alongside each UDP datagram
2. `noise/socket_ecn.go` `ecnReader.ReadFromUDP` parses the TOS byte; `isCEMarked(tos)` checks bottom two bits
3. On CE: `noiseConn.RecordCEBytes(n)` adds the datagram size to an atomic counter
4. Next outbound CompositeACK: `NoiseSession.sendCompositeACK` drains the counter via `noiseConnCE.DrainCEBytes()` and folds the total into `CACKHasECN` + `CEBytes` extension (32-bit, clamped to MaxUint32)
5. Remote sender's `handleACK` calls `congestion.Controller.OnCE(bytes)`

**Controller reactions:**
- **CUBIC** (`congestion/cubic.go:OnCE`): treat as loss — cwnd reduction (β=0.7), enter congestion avoidance
- **BBRv2** (`congestion/bbr.go:OnCE`): enter ProbeRTT to drain queue and discover updated min RTT
- **Advantage:** reacts one RTT *before* loss would otherwise trigger — smoother throughput, lower tail latency

ECN is opportunistic: if the kernel rejects the setsockopt (exotic configurations) or the platform is js/wasm, `ecnReader.Enabled()` returns false and the congestion controller falls back to loss-based signals only. Operator-visible: the noise listener logs `"ECN cmsg delivery enabled on <addr>"` at startup when the kernel accepts the option.

### 9.4 Send-Time Pacing

Two pacing strategies, matched to congestion controller:

| Controller | Pacer | Mechanism |
|-----------|-------|-----------|
| CUBIC | Token bucket (`Pacer`) | Rate = cwnd/RTT, 64KB burst capacity |
| BBRv2 | Send-time scheduler (`SendTimePacer`) | `TimeUntilSend(n) = lastSend + n/rate - now`. No credit accumulation — smoother than token bucket |

The `SendTimePacer` computes precise inter-packet intervals from the BBRv2 pacing rate. `OnSend(n)` advances `lastSend`. This eliminates burstiness that token-bucket approaches introduce.

### 9.5 Application Signal

`Session.CongestionWindow()` returns the current cwnd in bytes. `Session.EstimatedBandwidth()` returns the estimated available bandwidth in bytes/sec. Applications use these for adaptive behavior:
- Screen streaming: adjust compression quality based on bandwidth
- File transfer: adjust chunk size based on cwnd
- Telemetry: adjust batch flush interval

---

## 10. Priority Scheduling

### 10.1 Algorithm

Weighted Fair Queuing (WFQ) via virtual finish time:

- Each stream has a weight (1-255) and optional dependency (parent stream)
- Virtual finish time = `deficit + frame_size / weight`
- Stream with lowest finish time sends next
- Higher weight -> smaller increment -> more bandwidth share

### 10.2 Starvation Prevention

Streams with weight 255 are guaranteed to never be starved by lower-weight traffic. The WFQ algorithm ensures that even the lowest-weight stream eventually gets a turn — just proportionally less often.

---

## 11. Forward Error Correction

### 11.1 Algorithm

Three FEC strategies: XOR-based (lightweight), interleaved XOR (burst recovery), and Reed-Solomon (arbitrary k,m recovery).

### 11.2 FEC Levels

FEC is configurable per stream via `StreamConfig.FECLevel`:

| Level | Value | Strategy | Group Size | Overhead | Recovery | Use Case |
|-------|-------|----------|------------|----------|----------|----------|
| FECNone | 0 | — | — | 0% | — | Streams with application-level recovery (gossip, keepalive, control) |
| FECBasicXOR | 1 | XOR | 4 | 25% | 1 lost frame per group | General purpose (RPC, dynamic streams) |
| FECInterleaved | 2 | Interleaved XOR | 2 x 4 | 50% | Burst of 2 consecutive losses | Lossy links, critical data, realtime |
| FECReedSolomon | 3 | Reed-Solomon | k=8, m=2 | 25% | Any 2 lost frames per group | High-loss environments, screen streaming |

### 11.3 BasicXOR (FECBasicXOR = 1)

XOR-based FEC with a group size of 4. One repair packet is generated per group by XOR-ing all 4 data payloads. If exactly one data frame is lost, it is recovered from the repair packet without retransmission. Overhead: 25% (1 repair per 4 data).

### 11.4 Interleaved XOR (FECInterleaved = 2)

Two XOR groups are interleaved by frame index offset:

- **Group A:** even-indexed frames [0, 2, 4, 6] -> repair A
- **Group B:** odd-indexed frames [1, 3, 5, 7] -> repair B

Losing 2 consecutive frames (e.g., frames 3 and 4) puts each in a different group, making both recoverable. This handles burst loss of up to 2 consecutive packets.

- **Overhead:** 50% (2 repair packets per 8 data frames)
- **Burst recovery:** 2 consecutive packet losses
- **Per-group size:** Configurable (default 4 per sub-group, 8 total)
- **Encoder:** `InterleavedFECEncoder` tracks frame index and routes even/odd frames to separate `FECEncoder` instances
- **Decoder:** `InterleavedFECDecoder` uses two independent `FECDecoder` instances, one per interleave group

Implementation: `reliability/fec_interleaved.go`

### 11.5 Reed-Solomon (FECReedSolomon = 3)

Reed-Solomon erasure coding via GF(2⁸) Galois field arithmetic. Default configuration: k=8 data shards, m=2 parity shards.

- **Overhead:** 25% (2 parity per 8 data, equivalent to BasicXOR)
- **Recovery:** Any 2 lost frames per group (vs XOR's 1), regardless of position
- **Performance:** SIMD-accelerated encoding/decoding (AVX2/AVX-512/NEON) via `klauspost/reedsolomon`
- **Encoder:** `RSEncoder` encodes k data frames into m parity frames using Vandermonde matrix
- **Decoder:** `RSDecoder` tracks received data+parity shards per group, calls `Reconstruct()` when ≥k shards received
- **Group tracking:** Groups keyed by GroupID; deterministic eviction (min-groupID) when exceeding max groups
- **Shard alignment:** All shards zero-padded to max payload length in group

Implementation: `reliability/fec_rs.go`

### 11.6 Wire Format

FEC_REPAIR frame (Type 0x0C) payload:

```
[GroupID:4]  — FEC group identifier (monotonically increasing)
[Index:1]    — Repair packet index (for XOR: always = group_size. For RS: k, k+1, ..., k+m-1)
[Total:1]    — Total frames in group (data + repair)
[Repair:var] — XOR of all data payloads (XOR modes) or RS parity shard (RS mode)
```

RS parity shards are the same size as the largest data payload in the group.

### 11.7 Recovery

**XOR modes:** When exactly one data frame from a group is missing:

```
recovered_payload = repair_xor ^ received_frame_0 ^ received_frame_1 ^ ... (all except missing)
```

If two or more frames are missing in the same sub-group, FEC cannot recover — the reliability engine's retransmission handles it.

**Reed-Solomon:** When up to m data frames are missing, the decoder collects all received data and parity shards. If ≥k total shards are received (any combination of data+parity), the original k data shards are reconstructed via matrix inversion over GF(2⁸).

### 11.8 Disabled Streams

FEC is disabled (FECNone) on streams used for gossip, keepalive, and control. These streams have application-level recovery: gossip re-syncs every 10-30s, keepalive retries 3 times before declaring dead, and control has its own handshake retry logic. Disabling FEC on these streams saves 200-600 KB per Noise connection.

---

## 12. Retransmission

### 12.1 RTT Estimation (Jacobson/Karels, RFC 6298)

```
First sample:
  SRTT = R
  RTTVAR = R / 2

Subsequent samples:
  RTTVAR = (1 - 0.25) * RTTVAR + 0.25 * |SRTT - R|
  SRTT   = (1 - 0.125) * SRTT + 0.125 * R

RTO = SRTT + max(1ms, 4 * RTTVAR)
RTO clamped to [200ms, 60s]
```

### 12.2 Karn's Algorithm

RTT samples from retransmitted frames are NOT used for SRTT/RTTVAR computation (ambiguous which transmission the ACK acknowledges).

### 12.3 Retransmission Timer

- On send: start timer = RTO
- On ACK: cancel timer, update SRTT
- On timeout: retransmit, double RTO (exponential backoff), cap at 60s
- On bitmap gap detection: fast retransmit if (largestAcked - missingSeqNo) >= 3 (reorder threshold)

### 12.4 Composite ACK Integration

Retransmission decisions are driven by the Composite ACK (see section 2.8):

- **Cumulative ACK (BaseACK):** All entries <= BaseACK are permanently removed from the retransmit queue.
- **Bitmap:** bit=1 marks received, bit=0 marks implicit gap candidate. Fast retransmit triggered after reorder threshold (3) is exceeded.
- **Extended ranges:** ACK all SeqNos within each range (for gaps beyond bitmap window).
- **Dropped ranges:** Permanently remove from retransmit queue (receiver has given up on these).
- **Stall detection:** No progress for 2xSRTT triggers probe retransmit of oldest unacked frame.

---

## 13. Identity

### 13.1 PeerID

8-byte truncated fingerprint of the node's Ed25519 public key:

```
PeerID = SHA-256(public_key)[:8]
```

### 13.2 Identity Table

Each session maintains a mapping: `PeerID <-> full NodeID string`. Populated during session establishment (both sides exchange full NodeIDs). The mapping enables:

- Frame routing: relay nodes inspect ReceiverID without decrypting payload
- Fast dispatch: O(1) lookup by PeerID instead of string comparison

### 13.3 WHOIS Resolution

When a frame arrives with an unknown SenderID PeerID:

1. Receiver sends WHOIS request: `[unknown_PeerID:8][0x00]`
2. Sender responds: `[PeerID:8][0x01][NodeID_len:2][NodeID:var][PubKey:32]`
3. Receiver verifies PubKey matches PeerID (SHA-256[:8])
4. Receiver registers in identity table

Latency: sub-100ms (direct frame exchange) vs 10-30s (gossip convergence).

---

## 14. NAT Traversal

### 14.1 Problem

Two peers behind NAT cannot connect directly. Without intervention, all traffic routes through relay infrastructure.

### 14.2 NAT Behaviour Discovery (RFC 5780)

Aether classifies NAT behaviour using two independent dimensions:

**Mapping behaviour** (3 queries to 2 STUN servers):

| Value | Mapping Type | Description |
|-------|-------------|-------------|
| 0 | EIM | Endpoint-Independent Mapping — same mapped address regardless of destination |
| 1 | ADM | Address-Dependent Mapping — mapped address changes per destination IP |
| 2 | APDM | Address+Port-Dependent Mapping (symmetric) — mapped address changes per destination IP:port |

**Filtering behaviour** (2 additional tests):

| Value | Filtering Type | Description |
|-------|---------------|-------------|
| 0 | EIF | Endpoint-Independent Filtering — accepts from any source |
| 1 | ADF | Address-Dependent Filtering — accepts from known IPs |
| 2 | APDF | Address+Port-Dependent Filtering — accepts from known IP:port pairs |

Implementation: `nat/stun.go`

### 14.3 RENDEZVOUS Protocol

1. Peer A wants to connect to Peer B. Both are connected to relay node R.
2. A sends RENDEZVOUS to R: `[B_PeerID:8][A_observed_ip:16][A_port:2][A_mapping:1][A_filtering:1]`
3. R sends RENDEZVOUS to B: `[A_PeerID:8][A_observed_ip:16][A_port:2][A_mapping:1][A_filtering:1]`
4. R sends RENDEZVOUS to A: `[B_PeerID:8][B_observed_ip:16][B_port:2][B_mapping:1][B_filtering:1]`
5. Strategy engine selects the appropriate hole-punch method (see below)
6. If all methods fail, fall back to relay

### 14.4 Hole-Punch Strategies

| Peer A Mapping | Peer B Mapping | Strategy | Expected Success |
|---------------|---------------|----------|------------------|
| EIM | EIM | Simultaneous open | >90% |
| EIM | ADM/APDM | Asymmetric punch (A opens, B sends) | ~70% |
| ADM | ADM | UPnP → simultaneous open | ~60% |
| APDM | APDM | UPnP → birthday paradox → relay | ~40% (birthday) |
| Any | Any (blocked) | Relay fallback | 100% |

**Simultaneous open:** Both peers send UDP packets to each other's reflexive addresses at the same time. Works when both NATs have EIM mapping.

**Asymmetric punch:** The EIM peer opens first (predictable port), then the symmetric peer sends to it.

**Birthday paradox port prediction:** For APDM↔APDM (worst case). Open N source ports, probe N×M candidate port combinations. With N=256: ~40% success probability per attempt.

Implementation: `nat/holepunch.go`, `nat/birthday.go`

### 14.5 Port Mapping (UPnP / NAT-PMP / PCP)

Automatic gateway discovery and external port mapping. Tried in preference order: PCP → NAT-PMP → UPnP IGD.

- `PortMapper.Discover()` — probe gateway for supported protocols
- `PortMapper.RequestMapping(internal, external, protocol, ttl)` — request port mapping
- `PortMapper.ReleaseMapping()` — release on shutdown

Implementation: `nat/portmap.go`

### 14.6 Strategy Engine

`nat.Strategy.PickMethod(local, remote)` returns the recommended `PunchMethod` without performing I/O, using the RFC 5780 behaviour classification of both peers:

1. Either peer EIM → `PunchDirect` (simultaneous open viable)
2. Port mapper available → `PunchUPnP` (cheaper than prediction)
3. Both symmetric, no port mapper → `PunchPortPrediction` (birthday paradox)
4. No path viable → `PunchRelay`

`nat.Strategy.Connect(ctx, local, remote)` returns the chosen method plus `ErrNoPath` when all primitives are exhausted. Callers drive the actual probe-send.

Implementation: `nat/strategy.go` (engine), `nat/behaviour.go` (`DetectNATBehaviour`), `nat/holepunch.go` / `nat/birthday.go` / `nat/portmap.go` (primitives).

### 14.7 Consumer Integration (HSTLES Runtime / ORBTR Agent)

The HSTLES mesh runtime and ORBTR agent both expose the strategy engine via thin wrappers so consumers don't need to know about `nat.Strategy` internals:

**HSTLES `Runtime`** (`mesh/node/runtime.go`):
- `Runtime.DiscoverNAT(ctx)` — idempotent; runs `DetectNATBehaviour` post-STUN, stores result + constructs Strategy
- `Runtime.NATBehaviour()` — returns current `nat.NATBehaviour` snapshot
- `Runtime.NATStrategy()` — returns the Strategy engine (nil before DiscoverNAT)
- `Runtime.PickTraversalMethod(remote nat.NATBehaviour) nat.PunchMethod` — single-call decision for dial-path consumers

**ORBTR agent `meshTransport`** (`wire/transport.go`):
- Same three methods surfaced identically on the agent's mesh transport so peer-connection code can query without importing HSTLES.

Dial-path integration points: `peer_connections.go:833` in HSTLES, `wire/peers.go:connectDirect` in agent — both can consult `PickTraversalMethod` before attempting the default direct-dial chain and route straight to the recommended punch primitive instead.

---

## 15. Version Negotiation — REMOVED

Aether has no wire-level version negotiation. There is one wire protocol; identity and version are established by the underlying transport crypto layer (Noise XX/XK static keys, QUIC TLS handshake, WebSocket Ed25519 header, gRPC metadata). The `NegotiateMode` / `ModeAether` / `ModeString` APIs that existed in v5.x / v6.0 were removed in the HWP→Aether consolidation — they served a world where multiple wire formats coexisted, which no longer exists.

Backward-compat note: peers running v5.x or v6.0 code that tried to exchange a 4-byte negotiation header will now see the first 4 bytes of an Aether frame instead. The session will fail with a codec error at the first read — this is the expected behaviour because those older peers also speak a different frame codec, so they could not interoperate anyway.

---

## 16. Transport Classes

Transports are classified by their packet-level behavior. The class determines per-transport tuning parameters.

### 16.1 Classes

| Value | Class | Transports | Description |
|-------|-------|-----------|-------------|
| 0 | ClassRAW | Noise-UDP, QUIC | Packet-oriented. Full Aether protocol with aggressive retransmit and congestion control. |
| 1 | ClassSTREAM | TCP, TLS | Byte-stream. Conservative retransmit (TCP handles), reduced keepalive. |
| 2 | ClassPROXY | WebSocket, gRPC | Proxy-buffered. No retransmit (transport handles), increased keepalive frequency (prevent proxy timeout), reduced max frame size. |

### 16.2 Per-Class Defaults

| Parameter | ClassRAW | ClassSTREAM | ClassPROXY |
|-----------|----------|-------------|------------|
| KeepaliveInterval | 15s | 30s | 10s |
| MaxFrameSize | 1,400 bytes | 65,536 bytes | 32,768 bytes |
| RetransmitEnabled | Yes | No | No |
| AggressiveRetransmit | Yes | No | No |

Implementation: `transport_class.go`

---

## 17. Per-Transport Layer Activation

The protocol adapts to each transport's native capabilities. Aether layers are only activated when the transport does not provide them natively.

| Layer | Noise-UDP | TCP/TLS | WebSocket | QUIC | gRPC |
|-------|-----------|---------|-----------|------|------|
| Frame codec (encode/decode) | **Active** | **Active** | **Active** | Skip | Skip |
| Stream multiplexing | **Active** | **Active** | **Active** | Native streams | Native streams |
| Reliability (Composite ACK/retransmit) | **Active** | Skip (TCP) | Skip (TCP) | Skip (QUIC) | Skip (HTTP/2) |
| Flow control (WINDOW) | **Active** | **Active** | **Active** | Skip (QUIC) | Skip (HTTP/2) |
| Congestion (CUBIC/BBR) | **Active** | Skip (TCP) | Skip (TCP) | Skip (QUIC) | Skip (HTTP/2) |
| FEC (XOR repair) | **Active** | Skip | Skip | Skip | Skip |
| Anti-replay window | **Active** (DATA only) | Skip | Skip | Skip | Skip |
| Priority scheduler (WFQ) | **Active** | **Active** | **Active** | Skip | Skip |
| Encryption (AEAD) | Skip (Noise) | Skip (TLS) | Skip (TLS) | Skip (TLS) | Skip (TLS) |
| Identity (PeerID) | Skip (Noise key) | Skip (cert) | Skip (header) | Skip (cert) | Skip (metadata) |

**Bold = Aether provides. Skip = transport provides natively.**

**Flow control on TCP/WS:** TCP and WebSocket enforce flow control at the Aether level (WINDOW frames are active), but `Consume()` errors are ignored on these transports — TCP provides native backpressure as a safety net. On Noise-UDP, flow control is enforced fully and `Consume()` failures will block sends.

**Anti-replay on Noise-UDP:** Anti-replay is only active on Noise-UDP, and only for DATA frames. Control frames (SeqNo=0) bypass the replay window on all transports. See section 7 for details.

---

## 18. AEAD Additional Data Layout

For authenticated encryption, the first 38 bytes of the frame header serve as AEAD additional data. This authenticates the header without encrypting it.

```
AD bytes [0:38]:
  SenderID   [0:8]    — verified: frame came from claimed sender
  ReceiverID [8:16]   — verified: frame intended for us
  StreamID   [16:24]  — verified: frame belongs to claimed stream
  Type       [24]     — verified: frame type not tampered
  Flags      [25]     — verified: flags not tampered
  SeqNo      [26:30]  — verified: sequence not tampered
  AckNo      [30:34]  — verified: acknowledgment not tampered
  Length     [34:38]  — verified: payload boundary not tampered
```

Relay nodes can inspect `SenderID` and `ReceiverID` for routing decisions without decrypting the payload.

---

## 19. Error Handling

### 19.1 Stream Errors

| Error | Response |
|-------|----------|
| Unknown StreamID in DATA frame | Drop silently (unless SYN flag set -> implicit open) |
| RESET received | Close stream, deliver error to application |
| Flow control violation (send without credit) | Send RESET with reason FlowCtrl(3) |
| Stream idle timeout | Send RESET with reason Timeout(4) |

### 19.2 Connection Errors

| Error | Response |
|-------|----------|
| Frame decode error | Close connection (corrupted wire) |
| Frame validate failure (unknown Type, oversize, etc.) | Drop frame + `reportAbuse(ReasonMalformedFrame)` |
| AEAD auth failure | Drop frame + `reportAbuse(ReasonDecryptFail)` (tampered or replayed) |
| GOAWAY received | Stop opening new streams, drain existing |
| Keepalive timeout (3 x interval) | Close connection |
| Anti-replay rejection | Drop frame + `reportAbuse(ReasonReplayDetected)` |
| Stream-cap overflow | Send RESET(Refused) + `reportAbuse(ReasonStreamRefused)` |
| Composite ACK guard tripped (§34 S1) | Drop ACK + `reportAbuse(ReasonACKValidation)` |
| Abuse score exceeds threshold | Send `GOAWAY(Error=1)` + close session |

The GOAWAY frame currently uses `Reason=1 (Error)` for all non-normal shutdowns including abuse-score trips. A dedicated `GoAwayPeerAbuse` reason code may be added in a future wire-format revision; consumers distinguish abuse trips from other errors by reading the session's `PeerAbuseScore()` before/after close.

### 19.3 Fatal vs Transient Errors

| Error Type | Action |
|-----------|--------|
| EOF / connection reset / broken pipe | **Fatal** — close session, trigger reconnection |
| Exchange timeout (gossip) | **Transient** — continue loop, let keepalive decide |
| AEAD auth failure | **Transient** — drop frame, don't close session |
| Flow control blocked | **Transient** — wait for WINDOW, don't close |

---

## 20. Latency Classes

Three scheduling classes with strict priority between them:

| Class | Value | Description | Frames |
|-------|-------|-------------|--------|
| REALTIME | 0 | Strict priority, never queued behind BULK. Bandwidth-capped at 10%. | PING, PONG, WHOIS, RENDEZVOUS, input events, emergency policy |
| INTERACTIVE | 1 | Medium priority. Served after all REALTIME, before BULK. | RPC, screen key frames, tunnels, normal policy |
| BULK | 2 | Lowest priority. Gets remaining bandwidth. WFQ within class. | Gossip, telemetry, file transfer, screen deltas |

Scheduler: strict priority between classes -> WFQ by weight within each class.

## 21. Connection Migration

Session survives IP/port/transport changes via `TypeHANDSHAKE(AddressMigration)`. The migration payload is a fixed 74-byte structure carrying nonce + timestamp + new address + HMAC:

```
MigrationPayloadSize = 74 bytes:
  [ConnectionID:8][Nonce:8][Timestamp:8][NewAddr_IP:16][NewAddr_Port:2][HMAC-SHA256:32]
```

| Field | Size | Notes |
|-------|------|-------|
| ConnectionID | 8 | Random bytes, generated at session creation; binds the payload to a specific session so cross-session replay fails |
| Nonce | 8 | Random per migration attempt; replay-protection key into `seenNonces` cache |
| Timestamp | 8 | Unix nanoseconds; payloads older than `MigrationTokenTTL` are rejected |
| NewAddr_IP | 16 | IPv6-mapped representation (IPv4 maps into `::ffff:a.b.c.d`) |
| NewAddr_Port | 2 | Big-endian uint16 |
| HMAC-SHA256 | 32 | HMAC over `ConnectionID ‖ Nonce ‖ Timestamp ‖ NewAddr_IP ‖ NewAddr_Port` keyed with the session's AuthKey from the keyring |

**Validation** (`migration/migration.go:ValidateMigration`):

1. Decode 74-byte payload; reject if short
2. Verify HMAC using session's AuthKey (constant-time compare)
3. Check ConnectionID matches current session's ConnectionID
4. Check Timestamp is within `MigrationTokenTTL` window (rejects stale + future-dated tokens)
5. Check Nonce not in `seenNonces` cache (FIFO-bounded, `MigrationSeenCacheSize` entries); on success, record nonce
6. Update peer address; continue session on new path

The nonce cache prevents an attacker who observes an on-the-wire migration payload from replaying it against the same session later. The timestamp bound prevents pre-recorded payloads from being replayed after the attacker obtains the session key via some other means.

Implementation: `migration/migration.go`.

## 22. Deadline-Based Reliability

`StreamConfig.MaxAge` — frames older than this are dropped:
- By sender: skip retransmission if `time.Since(sentAt) > MaxAge`
- By receiver: drop on delivery if expired
- Default: 0 (no deadline)

## 23. Short Headers (v2)

After session establishment, most frames can use compact short headers instead of the full 50-byte header. The first byte (indicator) determines the format. Indicators in the range `0x00`-`0x7F` are interpreted as a full 50-byte header (the first byte falls within valid Type values). Indicators `0x82`-`0x87` select a short header format.

### 23.1 Indicator Byte Registry

| Range | Meaning |
|-------|---------|
| `0x00`-`0x7F` | Full 50-byte header (byte is the Type field) |
| `0x80`-`0x81` | Reserved (v1 deleted indicators, never reuse) |
| `0x82` | Data short header |
| `0x83` | Control short header |
| `0x84` | ACK short header |
| `0x85` | Batch short header |
| `0x86` | Data varint header |
| `0x87` | Encrypted data short header |
| `0x88`-`0x8F` | Reserved for future short header formats (detection range) |
| `0x90`-`0xF7` | Reserved (not matched by `IsShortHeader`) — currently routed to full-header decode + will fail Type check; do not use for new header formats without updating the detection range |
| `0xF8`-`0xFA` | Reserved — resume sub-protocol prefixes (`resumeAcceptPrefix`=0xF8, `resumeRejectPrefix`=0xF9, `resumePrefix`=0xFA) — see §31 |
| `0xFB`-`0xFC` | Reserved |
| `0xFD` | `dialNoncePrefix` — routes handshake responses via pending-dial table, see `noise/session.go` |
| `0xFE` | `retryPrefix` — S3 stateless retry cookie, see §34.2 |
| `0xFF` | Reserved (v1 deleted indicator, never reuse) |

**Detection range**: `IsShortHeader(b)` in `codec_short.go` returns true only for `0x82 <= b <= 0x8F`. Bytes `0x90`-`0xF7` are NOT detected as short headers — they fall through to the full-header decode path, which will fail `Type.IsValid()` and route to abuse scoring via `Frame.Validate()`. Bytes `0xF8`-`0xFE` are intercepted by the UDP listener (`noise/session.go:runReader`) for the resume / retry / dial-nonce sub-protocols BEFORE reaching the Aether codec.

### 23.2 Short Header Formats

| Indicator | Format | Size | Use Case |
|:-:|--------|:-:|----------|
| `0x82` | Data short | 9 bytes | Unencrypted DATA, uint16 StreamID + uint32 Length |
| `0x83` | Control short | 4 bytes | PING/PONG/CLOSE/RESET (no payload) |
| `0x84` | ACK short | 11 bytes (lite) or 3+N (full) | Composite ACK |
| `0x85` | Batch | 2+N x sub | Multiple frames per write |
| `0x86` | Data varint | 6-10 bytes | Small DATA, varint Length |
| `0x87` | Encrypted data | 9 bytes | Encrypted DATA, Nonce-in-payload |

#### 23.2.1 Data Short (`0x82`) — 9 bytes

```
[0x82:1][StreamID:2][SeqDelta:2][Length:4][Payload:var]
```

- StreamID is uint16 (supports streams 0-65535; streams > 65535 require full header)
- **SeqDelta** is a uint16 delta from the last sequence number on this stream (not the raw SeqNo). The decoder reconstructs the full SeqNo: `seqNo = lastSeqNo + seqDelta`
- Length is uint32 payload length
- SenderID/ReceiverID inherited from session state
- Type is implicitly DATA (0x01), Flags implicitly 0x00
- A full 50-byte header is sent every 64 frames per stream (`ShortHeaderFullInterval`) for state resynchronization

Implementation: `codec_short.go` — `ShortDataSize = 9`, field at offset [3:5] is `seqDelta`

#### 23.2.2 Control Short (`0x83`) — 4 bytes

```
[0x83:1][Type:1][StreamID:2]
```

- Type: PING(0x06), PONG(0x07), CLOSE(0x03), RESET(0x04)
- No payload, no SeqNo, no Length
- Used for high-frequency keepalive without header overhead

#### 23.2.3 ACK Short (`0x84`) — 11 bytes (lite) or 3+N (full)

**ACK-lite (no gaps):**
```
[0x84:1][StreamID:2][BaseACK:4][AckDelay:2][BitmapLen:1=0][Flags:1]
```
Total: 11 bytes

**ACK-full (gaps exist):**
```
[0x84:1][StreamID:2][BaseACK:4][AckDelay:2][BitmapLen:1][Bitmap:N][Flags:1][extensions...]
```
Total: 3 + CompositeACK payload size

- Composite ACK payload format is identical to section 2.8
- StreamID identifies which stream is being acknowledged

#### 23.2.4 Batch (`0x85`) — 2+N x sub bytes

```
[0x85:1][Count:1][SubFrame_0][SubFrame_1]...[SubFrame_N-1]
```

- Count: number of sub-frames (1-255)
- Each sub-frame is a complete short header frame (any format 0x82-0x87)
- Enables multiple frames to be sent in a single write syscall
- Sub-frames MUST NOT be nested batches (no 0x85 inside 0x85)

#### 23.2.5 Data Varint (`0x86`) — 6-10 bytes

```
[0x86:1][StreamID:2][SeqDelta:2][Length:varint][Payload:var]
```

- Length is encoded as a varint (1-5 bytes), saving space for small payloads
- Optimal for payloads < 128 bytes (Length fits in 1 byte, total header = 6 bytes)
- Otherwise identical to Data Short (0x82)

#### 23.2.6 Encrypted Data (`0x87`) — 9 bytes

```
[0x87:1][StreamID:2][SeqDelta:2][Length:4][EncryptedPayload:var]
```

- Header is identical to Data Short (0x82) but indicates encrypted payload
- Nonce is carried inside the payload envelope (not in the header)
- Encrypted payload envelope: `[Nonce:12][Ciphertext:var][Tag:16]`
- Length field includes the full envelope: 12 (nonce) + ciphertext_len + 16 (tag)
- AEAD additional data = the 9-byte short header itself (all bytes before payload)

### 23.3 Session State

Short headers omit fields that are constant or derivable from session state:

| Field | Source |
|-------|--------|
| SenderID | Established during session handshake, shared for all frames |
| ReceiverID | Established during session handshake, shared for all frames |
| Nonce | For `0x87`: carried in payload envelope. For others: not applicable (unencrypted) |
| AckNo | Omitted; use dedicated ACK short (`0x84`) or piggyback in full header |
| Flags | Implicit per format (e.g., `0x87` implies ENCRYPTED) |

### 23.4 Per-Stream SeqDelta State

Each stream tracks its own independent sequence state for delta compression:

- **Sender side:** Maintains per-stream `lastSeqNo`. SeqDelta = `currentSeqNo - lastSeqNo`.
- **Receiver side:** Reconstructs full SeqNo: `seqNo = lastSeqNo + seqDelta`.
- SeqDelta in short headers is uint16 (max delta 65535). If the delta exceeds 65535, a full header is used.
- SeqNo is scoped to a stream — each stream has independent tracking starting at 0.
- On stream OPEN (or implicit open via FlagSYN), SeqNo resets to 0.

### 23.5 Implicit OPEN via FlagSYN

Streams can be opened implicitly by sending a DATA frame with `FlagSYN` (0x02) set in a full 50-byte header. This combines OPEN + DATA into a single frame, avoiding a separate OPEN round-trip. Short headers do NOT carry flags, so the first frame on a new stream MUST use a full header with FlagSYN set. Subsequent frames on that stream can use short headers.

Sequence:
1. Sender sends full header DATA frame with `FlagSYN | reliability | priority` on new StreamID
2. Receiver sees FlagSYN, opens stream with specified parameters, delivers payload
3. All subsequent frames on that stream use short headers

### 23.6 When to Use Full Headers

The full 50-byte header remains the canonical format for:

- **First frame on a new stream** (FlagSYN required for implicit open)
- **Resynchronization** (after connection migration, long idle, or error recovery)
- **Periodic resync** (every 64 frames per stream — `ShortHeaderFullInterval`)
- **WINDOW_UPDATE** frames (Type 0x05 — not representable as short header)
- **GOAWAY** frames (Type 0x0B — connection-level, no short form)
- **FEC_REPAIR** frames (Type 0x0C)
- **HANDSHAKE** frames (Type 0x10)
- **NETWORK_CONFIG** frames (Type 0x0F)
- **Streams with ID > 65535** (short header StreamID is uint16)
- **Frames requiring explicit flags** (COMPRESSED, ANTIREPLAY, PRIORITY)
- **Any frame where the sender needs piggyback AckNo**

---

## 23A. Compression Decision Logic

The encoder follows a 13-step decision tree to select the optimal header format for each outgoing frame:

```
 1. Is this the first frame on a new stream?
    YES -> Full header (FlagSYN required)

 2. Is the StreamID > 65535?
    YES -> Full header (short headers use uint16 StreamID)

 3. Does the frame require explicit flags (COMPRESSED, ANTIREPLAY, PRIORITY)?
    YES -> Full header

 4. Does the frame need piggyback AckNo?
    YES -> Full header

 5. Is the frame a WINDOW_UPDATE, GOAWAY, FEC_REPAIR, HANDSHAKE, or NETWORK_CONFIG?
    YES -> Full header (no short form exists)

 6. Is the frame a PING, PONG, CLOSE, or RESET with no payload?
    YES -> Control short (0x83, 4 bytes)

 7. Is the frame an ACK (Type 0x08)?
    YES -> ACK short (0x84, 11 bytes lite / 3+N full)

 8. Is the frame encrypted (ENCRYPTED flag)?
    YES -> Encrypted data short (0x87, 9 bytes + nonce-in-payload envelope)

 9. Are there multiple frames queued for the same write?
    YES -> Batch (0x85) wrapping the individual short-encoded sub-frames

10. Is the payload length < 128 bytes?
    YES -> Data varint (0x86, 6 bytes header)

11. Is the payload length < 16384 bytes (fits in 2-byte varint)?
    YES -> Data varint (0x86, 7 bytes header)

12. Otherwise, is it a plain DATA frame?
    YES -> Data short (0x82, 9 bytes)

13. Fallback -> Full header (50 bytes)
```

Steps are evaluated in order; the first match wins. The batch step (9) is applied as a wrapper after individual frames have been encoded by steps 6-8 and 10-12.

## 24. MTU-Aware Fragmentation

### 24.1 Problem

The Noise adapter sends entire payloads as single UDP datagrams regardless of size. A 100 KB gossip payload becomes a single ~100 KB UDP packet. The kernel fragments this into ~72 IP fragments. If any single fragment is lost, the entire datagram is silently dropped — no selective retransmit, no recovery. At 1% packet loss, the probability of losing at least one of 72 fragments is ~51%.

### 24.2 Design

`Send()` transparently fragments payloads exceeding the transport MSS into multiple Aether frames. Each fragment is independently tracked by the reliability engine (ACK, retransmit, FEC). `Receive()` reassembles fragments transparently. Callers never see fragmentation.

- **Noise-UDP:** Fragments at PMTU prober MSS (default 1400 bytes). Each fragment is one UDP packet — no IP fragmentation.
- **TCP/WS:** Fragments at MaxFrameSize (65536 for STREAM class, 32768 for PROXY class) to avoid head-of-line blocking. Interleaves with other streams' frames in the scheduler.

### 24.3 Fragment Header (4 bytes)

```
[0x46 0x52]  — magic "FR" (distinguishes from non-fragmented payloads)
[index:1]    — fragment position (0-255)
[total:1]    — total fragment count (1-255)
```

The fragment header is prepended to each fragment's payload. On receive, the presence of the `0x46 0x52` ("FR") magic at the start of the payload distinguishes fragmented from non-fragmented frames. Non-fragmented payloads are returned directly.

There is no explicit fragmentID field. The fragmentID is implicit — fragments in a group share contiguous SeqNos. The receiver groups fragments by deriving the first fragment's SeqNo: `firstSeqNo = seqNo - index`. In practice, the reassembly buffer uses an internal monotonic counter: `index=0` starts a new group, subsequent fragments (index > 0) join the current group.

Implementation: `adapter/fragment.go` — `fragHeaderSize = 4`

### 24.4 Reassembly

A reassembly buffer per stream groups fragments:

- When a fragment with index=0 arrives, a new group is created
- Subsequent fragments (index > 0) join the current group
- When all `total` fragments are received, the original payload is reconstructed by concatenating fragments in index order
- Incomplete fragment sets are discarded after a 10-second timeout (`fragTimeout`)
- Maximum fragment count of 255 supports payloads up to 255 × ~1200 bytes = ~306 KB

**DoS caps** (added in v6.1 to defend against fragment-flood attacks where an attacker sends index=0 fragments with never-completing totals to grow per-stream state):

| Limit | Constant | Default |
|-------|----------|---------|
| Concurrent reassembly groups per stream | `MaxGroupsPerStream` | 16 |
| Streams tracked in the fragment buffer | `MaxStreamsInFragBuffer` | 1024 |

On overflow: `CheckRelayPair`-style — new-group admission returns an error (caller drops the fragment), existing groups continue to accept fragments until complete or timed out.

### 24.5 Interaction with Reliability

Each fragment is a separate Aether frame with its own SeqNo. The existing reliability engine provides:

- **Per-fragment ACK/retransmit:** Lost fragments are individually retransmitted (not the whole payload)
- **FEC recovery:** XOR repair can recover one lost fragment per group without retransmit
- **Congestion pacing:** Fragment sends are paced by the congestion controller, preventing burst loss
- **Reorder tolerance:** Fragments arrive in any order; reassembly handles it

### 24.6 Small Payload Fast Path

Payloads smaller than `MSS - overhead` (where overhead = 50-byte Aether header + 16-byte Noise encryption tag) take the existing single-frame path with zero fragmentation overhead.

---

## 25. Virtual Wire Interface

### 25.1 Principle

An Aether stream is a virtual wire — indistinguishable from a TCP connection to the application layer. `io.Copy(stream.Conn(), file)` sends a 100 MB file, chunked, paced, and reliable. `http.Serve(stream.Conn(), handler)` serves HTTP over mesh. The application never knows it is running over Aether.

### 25.2 StreamConn

`Stream.Conn()` returns a `net.Conn` view of the stream:

```go
type Stream interface {
    Send(ctx context.Context, data []byte) error    // message-oriented
    Receive(ctx context.Context) ([]byte, error)    // message-oriented
    Conn() net.Conn                                  // byte-stream (virtual wire)
    StreamID() uint64
    // ... existing methods
}
```

The returned `net.Conn` (StreamConn) implements:

- **Read(p []byte):** Wraps `Receive()` with an internal read buffer. Returns partial reads when the caller's buffer is smaller than the received message. Adapts Aether's message-oriented framing to a byte stream.
- **Write(p []byte):** Auto-chunks at MaxFrameSize (after section 24 fragmentation). Each chunk calls `Send()`. The caller writes any size — Aether handles fragmentation at both the MaxFrameSize level and the MTU level.
- **Close():** Sends FIN on the stream.
- **SetDeadline / SetReadDeadline / SetWriteDeadline:** Creates per-call `context.WithDeadline` for timeout control. Integrates with Go's standard deadline-based I/O.
- **LocalAddr() / RemoteAddr():** Returns the session's local and remote mesh addresses.

### 25.3 Composition with Other Layers

Combined with MTU-aware fragmentation (section 24), configurable flow control (section 8), and the priority scheduler (section 10):

```
Write(data)
  -> split into MaxFrameSize chunks (section 25)
    -> each chunk calls Send() (section 24)
      -> Send() fragments at MTU if needed (Noise)
        -> fragments enter reliability engine (ACK/retransmit)
          -> fragments enter congestion controller (pacing)
            -> fragments enter priority scheduler (WFQ)
              -> wire
```

Flow control naturally paces the writer — `Write()` blocks when credit is exhausted, exactly like TCP backpressure.

### 25.4 Usage

```go
// File transfer over mesh
stream, _ := session.OpenStream(ctx, aether.StreamConfig{
    Priority:      aether.ClassBULK,
    InitialCredit: 2 * 1024 * 1024, // 2 MB window for throughput
})
io.Copy(stream.Conn(), file) // sends any size, chunked, paced, reliable

// HTTP over mesh
stream, _ := session.OpenStream(ctx, aether.StreamConfig{Priority: aether.ClassINTERACTIVE})
http.Serve(stream.Conn(), handler)
```

---

## 26. Transport Capabilities

### 26.1 Capability Struct

`TransportCapabilities` describes what a transport connection provides natively:

| Field | Noise-UDP | QUIC | WebSocket | gRPC |
|-------|-----------|------|-----------|------|
| NativeReliability | false | true | true | true |
| NativeOrdering | false | true | true | true |
| NativeEncryption | true | true | true | true |
| NativeMux | false | true | false | true |
| MaxMTU | 1400 | 65536 | 32768 | 65536 |
| Bidirectional | true | true | true | true |
| SupportsResume | true | false | false | false |
| SupportsMultipath | false | false | false | false |

Consumers derive their own quality models from these capabilities.

---

## 27. Observability Frame Types

| Code | Type | Payload |
|------|------|---------|
| 0x11 | STATS | RTT, loss%, cwnd, retransmits, frames, bytes, streams (34B) |
| 0x12 | TRACE | TraceID + per-hop entries (nodeID, timestamp, latency) |
| 0x13 | PATH_PROBE | ProbeID + variable padding for PMTU discovery |

## 28. Strict Profiles

| Profile | Name in `profile.go` | Transports | Active Layers |
|---------|----------------------|-----------|---------------|
| Aether-FULL | `ProfileFull` (`"A-FULL"`) | Noise-UDP | All: codec, mux, reliability, flow, congestion, FEC, anti-replay, scheduler, pacing, PMTU, FEC, resume, migration, abuse scoring |
| Aether-LITE | `ProfileLite` (`"A-LITE"`) | QUIC, TCP, WS, gRPC | Stream lifecycle, scheduler, flow control, abuse scoring, idle eviction, stream GC, control plane, observability |

Same session-API semantics across profiles — `Stream.Send()` / `Stream.Receive()` / `Session.OpenStream()` behave identically regardless of which profile the underlying adapter is running. The agnostic interfaces (`AbuseScoreCapable`, `IdleEvictable`, `CompressionCapable`) work uniformly on either profile.

## 29. Path MTU Discovery

Uses `TypePATH_PROBE` with increasing payload sizes. Discovered PMTU sets MSS for congestion control and fragmentation threshold (section 24). Re-probed every 10 minutes.

## 30. Multipath

### 30.1 Level 1 — Active/Standby

One primary path carries all traffic. One or more standby paths receive periodic probes (every 30s). Instant failover when the primary dies: the best standby is promoted to primary based on quality score. Failback occurs after a 60-second stability period.

### 30.2 Level 2 — Redundant Realtime

REALTIME-class frames are sent on ALL active+standby paths simultaneously. Deduplicated on receive by SeqNo. Data-class frames are sent only on the primary path.

Consumers enable Level 2 via `Manager.EnableRedundantRealtime()`. The manager's `ShouldSendRedundant(latencyClass)` returns true when redundant realtime is enabled, the frame is REALTIME class, and multiple paths exist.

### 30.3 Level 3 — Weighted Load Balance (WDRR)

Distributes non-REALTIME traffic across all active paths using **Weighted Deficit Round-Robin**. Each path accumulates a per-round byte budget proportional to its computed weight; the scheduler picks the path with the lowest bytes-scheduled-per-unit-weight cost (argmin of `bytesScheduled/weight`) on every send. Weights rebalance continuously via `RecordPathStats(session, rtt, loss)`.

**Weight formula** (`multipath.computePathWeight`):

```
w = Quality                                  // operator-supplied tier (protocol grade)
w *= 50 / (RTT_ms + 1)                       // RTT penalty, 50ms baseline; halves per +50ms
w *= 1 - 0.8 * loss                          // loss penalty; 100% loss → 0.2× weight
w = max(w, 1)                                // floor prevents zero-weight stalls
```

Bandwidth estimation is not currently folded into the weight — RTT and loss are the dominant signals on typical peer paths. If bandwidth measurement becomes available per-path, multiply by normalised bandwidth before the floor.

**Scheduler invariants:**
- `bytesScheduled` counters are halved periodically (when any path's counter exceeds 1MB) to keep deficits bounded
- Dead paths are excluded from selection
- Single-path peers fall through to `PrimarySession()` — no WDRR overhead

**Defaults (as of v6.1):** both `EnableRedundantRealtime` (L2) and `EnableWeightedLoadBalance` (L3) are activated on every multipath manager created by the HSTLES mesh runtime and the ORBTR agent. Consumers with multiple paths to a peer get L1/L2/L3 behaviour automatically.

**Cross-adapter wiring:**
- `GetMeshSession(nodeID)` now prefers `multipath.Manager.PrimarySession()` over the single-session map, so every caller benefits from active-path selection without opt-in
- `GetMeshSessionForBytes(nodeID, n)` routes through WDRR — preferred for bulk / non-REALTIME sends
- `GetAllMeshSessions(nodeID)` returns the full path set for REALTIME fanout

**Level 4 (true bandwidth aggregation):** deferred — requires coupled congestion control across paths (MPTCP-style), which is a substantive additional design.

Implementation: `multipath/manager.go` (library), `mesh/node/mesh_connection.go` (HSTLES wiring), `agent/internal/core/wire/peers.go` (agent wiring with `TopUpPaths` background establishment of additional paths).

## 31. Session Resume (0.5-RTT)

Aether implements 0.5-RTT session resumption over Noise-UDP. On subsequent reconnects to a previously-seen peer, the initiator skips the full XK/XX handshake by presenting a cached ticket and proving key possession via an AEAD tag in a single datagram — one round-trip less than a fresh handshake. The protocol is "0.5-RTT" not "0-RTT" because the initiator waits for the responder's accept before sending application data; this keeps the design replay-safe without needing to duplicate-detect 0-RTT frames.

### 31.1 Responder: Ticket Issuance

After a successful XK/XX handshake completes, the responder (`noise/handshake.go`):

1. Calls `TicketStore.IssueTicket(peerID, cs2, cs1, capsBits)` — encrypts the session state (peer ID, keys, nonces, caps, expiry) using the responder's local AES-256-GCM `TicketStore.key`
2. Constructs `resumeMaterial`:
   - `Opaque` — the encrypted ticket blob (152 bytes) for replay back to responder
   - `SendKey` — initiator-perspective send key (= responder's recv = cs1)
   - `RecvKey` — initiator-perspective recv key (= responder's send = cs2)
   - `Caps`, `ExpiresAt`
3. Populates the responder's OWN `initiatorTickets` cache (for the co-located symmetric-mesh case where both nodes dial each other)
4. Delivers the material to the remote initiator via `deliverResumeMaterial(nc, m)` — sends an Aether HANDSHAKE frame carrying `HandshakeResumeMaterial` payload, encrypted with `cs2` at nonce 0

**Nonce accounting**: delivery consumes `cs2` nonce 0 on both sides; subsequent session traffic uses nonce 1 onward. The ticket snapshot (captured at nonce 0 pre-consumption) remains valid — future resume creates fresh CipherStates starting from nonce 0 independently of the live session's current nonce.

### 31.2 Initiator: Ticket Reception

Initiator's `adapter/noise_dispatch.go` `handleHandshake` dispatches `HandshakeResumeMaterial` via interface probe (`resumeMaterialRecorder`):

1. `noiseConn.RecordResumeMaterial(data)` decodes via `decodeResumeMaterial`
2. Stores in `transport.initiatorTickets` keyed by remote NodeID

Cache is bounded (`DefaultTicketCacheSize = 4096` entries, FIFO eviction; lazy expiry on Lookup).

### 31.3 Resume Wire Protocol

Wire prefixes used only for the resume sub-protocol (chosen to avoid collision with `retryPrefix=0xFE` and `dialNoncePrefix=0xFD`):

| Prefix | Direction | Meaning |
|--------|-----------|---------|
| `0xFA` resumePrefix | Initiator → Responder | "I have a ticket; skip XK/XX" |
| `0xF8` resumeAcceptPrefix | Responder → Initiator | "Accepted; session established" |
| `0xF9` resumeRejectPrefix | Responder → Initiator | "Rejected; fall back to full handshake" |

**Resume request packet** (initiator):

```
[0xFA][opaqueLen:2 BE][opaqueTicket:opaqueLen][proofTag:16]
```

- `opaqueTicket` — verbatim replay of the responder-issued ticket
- `proofTag` — AEAD-seal of an empty plaintext using the initiator's send key (= responder's recv key, ticket.RecvKey). Proves the initiator actually holds the keys claimed by the ticket; defence against ticket theft

**Accept reply** (responder):

```
[0xF8][proofTag:16]
```

- `proofTag` — AEAD-seal of empty plaintext using responder's send key (= ticket.SendKey). Initiator verifies via decrypt with its recv key

**Reject reply** (responder):

```
[0xF9]
```

Single byte. Reasons for reject: ticket decrypt failed (expired, rotated ticket-key), replay detected (seen-nonce cache), proof-tag verify failed.

### 31.4 Replay Protection

Responder maintains `seenTicketCache` (`DefaultSeenTicketCacheSize = 16384` entries, FIFO eviction). The ticket's 12-byte GCM nonce serves as the replay key — guaranteed unique per `IssueTicket` call because nonce is generated via `crypto/rand`. Second presentation of the same ticket is rejected with `0xF9`.

### 31.5 Rollback Behaviour

Initiator's `tryResumeDial`:
- Accept (`0xF8`) + tag verifies → instantiate `noiseConn` from ticket's cipher states, return session
- Reject (`0xF9`) → evict cache entry for this peer, return `errResumeRejected`, caller falls back to full handshake
- Timeout / no reply / tag mismatch → fall back to full handshake

Resume attempt kicks in automatically in `NoiseTransport.Dial` before the full-handshake path, so callers using `Dial` get 0.5-RTT reconnect "for free" whenever a valid cached ticket exists.

### 31.6 Security Properties

- **Key freshness**: resume derives a NEW session from the ticket's captured keys (fresh CipherStates at nonce 0); the old live session continues independently. Forward secrecy is equivalent to the original handshake.
- **Authentication**: AEAD proof tags on both sides prove key possession before any session state is committed. Ticket alone is insufficient to resume — attacker needs both the opaque blob AND the plaintext keys, which only the original initiator cached.
- **Replay safety**: 0.5-RTT (not 0-RTT) design means no application data is sent with the resume request; nothing to replay. Resume requests themselves are deduped via `seenTicketCache`.
- **Ticket-key rotation**: `TicketStore.RotateKey(newKey)` keeps the previous key for the rotation overlap window so mid-rotation resume attempts still succeed.

### 31.7 Higher-Level Token Resume (Agent / HSTLES consumer layer)

Separate from the protocol-level 0.5-RTT resume above, the ORBTR agent and HSTLES mesh also run their own application-level resume token exchange via the control stream (`resume/token.go`, `resume/file_store.go`) — persisted to disk via `FilePeerStore` for cold-restart recovery of gossip watermarks and peer hints. That layer sits ABOVE aether and is orthogonal to the Noise-level ticket resume.

### 31.8 `HandshakeResumeMaterial` Inner Payload

The payload carried inside a `TypeHANDSHAKE(HandshakeResumeMaterial=4)` frame — this is what the responder sends to the initiator after handshake completion, wrapped in the standard Aether frame codec and encrypted via the just-derived cs2 state at nonce 0:

```
[opaqueLen:2 BE][opaqueTicket:opaqueLen][SendKey:32][RecvKey:32][Caps:4 BE][ExpiresUnixNano:8 BE]
```

| Field | Size | Notes |
|-------|------|-------|
| `opaqueLen` | 2 | Big-endian uint16; length of the encrypted ticket blob (typically 152 bytes — `ticketEncryptedSize`) |
| `opaqueTicket` | `opaqueLen` | The responder-encrypted ticket, verbatim; initiator replays this on resume without inspecting contents |
| `SendKey` | 32 | Initiator-perspective send key (= responder's recv key, cs1.UnsafeKey()). Plaintext — secrecy provided by the outer AEAD on the HANDSHAKE frame |
| `RecvKey` | 32 | Initiator-perspective recv key (= responder's send key, cs2.UnsafeKey()) |
| `Caps` | 4 | Big-endian uint32; capability flags negotiated in the original session (e.g. `capSessionTicket`, `capExplicitNonce`). Resume inherits the same caps |
| `ExpiresUnixNano` | 8 | Big-endian int64; ticket expiry timestamp; initiator evicts from cache after this time (independent of responder's ticket-key TTL) |

**Why plaintext keys are safe here**: the material rides inside a HANDSHAKE frame that's already AEAD-encrypted by cs2 at nonce 0 on the freshly-established session. Only the legitimate initiator (who completed the Noise handshake) can decrypt the HANDSHAKE frame and see the keys. The `opaqueTicket` is additionally encrypted with the responder's ticket-store key so the responder doesn't need to trust its own cache to validate future resume attempts — it can decrypt any ticket it issued from first principles.

Encode/decode: `noise/session_resume.go:encodeResumeMaterial` / `decodeResumeMaterial`.

Implementation: `noise/session_ticket.go`, `noise/session_resume.go`, `noise/handshake.go`, `adapter/noise_dispatch.go`.

---

## 32. Adaptive CPU Load-Shedding

The `AdaptiveController` monitors system CPU utilization and progressively disables expensive Aether features to prevent saturation.

### 32.1 Degradation Thresholds

| CPU Threshold | Feature Disabled | Re-enabled At |
|---------------|-----------------|---------------|
| > 70% | DEFLATE compression | <= 65% |
| > 80% | FEC (forward error correction) | <= 75% |
| > 90% | WFQ scheduler (falls back to FIFO) | <= 85% |

Features are re-enabled with hysteresis (5% below the disable threshold) to prevent oscillation.

**Encryption is an invariant** — the adaptive controller never disables per-frame AEAD encryption, transport-layer encryption, or authentication. Under extreme CPU pressure, the controller continues load-shedding compression / FEC / scheduler; if that's not enough, new sessions are rejected at admission control rather than compromise security guarantees. See `adaptive.go:104` for the explicit comment asserting this invariant.

### 32.2 Monitoring

CPU utilization is estimated from `runtime.NumGoroutine()` / `runtime.GOMAXPROCS(0)` as a heuristic. The controller checks every 5 seconds. Production deployments should use runtime/pprof or cgroup stats for more accurate measurement.

Implementation: `adaptive.go:AdaptiveController`

---

## 33. mDNS Discovery

Peers on the local network are discovered via mDNS using the service type:

```
_hstles-mesh._tcp.local.
```

mDNS announcements carry:
- **NodeID:** Mesh node identifier
- **Addresses:** Transport addresses (host:port)
- **Signature:** Ed25519 signature over `"MDNS:v1:<nodeID>:<addrs>"` to prevent announcement spoofing

Implementation: `discovery/mdns.go` — `MDNSServiceType = "_hstles-mesh._tcp.local."`

---

## 34. Security — S1–S9 Remediation (v6.1 Baseline)

Every deployed Aether session ships with the following security surface active by default:

| Item | Mitigation | Implementation |
|------|------------|----------------|
| **S1** Composite ACK scans bounded | Per-range size cap (`MaxACKRangeSize=1024`), max cumulative jump, suspicious-ACK counter feeds abuse score | `reliability/send_window.go` |
| **S2** FEC decoder pruning | 1-Hz tick, count cap (`MaxFECGroups=256`) + age cap (2×max SRTT, floor 2s) for XOR / Interleaved / Reed-Solomon decoders | `adapter/noise_reliability.go`, `reliability/fec*.go` |
| **S3** Handshake amplification | QUIC-style stateless retry cookie (HMAC-bound to source IP + nonce + expiry, 30s TTL); ON BY DEFAULT | `noise/retry.go`, `noise/handshake.go` |
| **S4** Migration token replay | HMAC bound to ConnectionID + 74-byte payload + nonce + timestamp; bounded seen-nonce cache | `migration/migration.go` |
| **S5** Stream-count exhaustion | `MaxConcurrentStreams` cap (1024 Noise / 256 TCP-family); RESET(Refused) + abuse report + streamRefused counter | `adapter/noise_stream.go`, `adapter/tcp.go` |
| **S6** Per-source handshake flood | LRU-bounded source-IP token bucket gates ALL inbound UDP before crypto work | `noise/ratelimit.go` |
| **S7** Peer abuse scoring | Generic `abuse.Score[K]` with exponential decay; 5 call sites (decrypt-fail, malformed-frame, ACK-validation, replay-detected, stream-refused) trip circuit breaker → GoAway + Close | `abuse/score.go`, `adapter/noise_session.go` |
| **S8** SeqNo wraparound | Diff > 2^31 rejected; `WrapsDetectedCount()` metric | `reliability/antireplay.go` |
| **S9** Relay scope WFQ | Cross-scope weighted fair queueing with preemption; `MaxTotalPairs` global cap + `ScopeWeights` + `RelayEvictions` metric | `noise/scope_limiter.go` |

### 34.1 Post-Remediation Hardening

Additional attack-surface fixes shipped after S1–S9:

- **Compression bomb guard** — `decompressPayload` uses `io.LimitReader(r, MaxPayloadSize)` so a 64-byte DEFLATE stream cannot expand to GB
- **Short-header Frame.Validate() gate** — v2 short-header decoders skip Validate(); `processIncomingFrame` re-gates before dispatch so unknown Types / oversize Length can't slip through
- **Idle session eviction** — `SessionIdleTimeout` (default 5m, configurable); `reliabilityTick` / TCP `housekeepingTick` closes sessions past the threshold
- **AckDelay lower bound** — peer reports < 0 or > elapsed are rejected so attacker can't deflate SRTT estimate
- **Log injection guard** — peer-supplied GOAWAY message formatted with `%q`
- **FlagANTIREPLAY always-on** for DATA frames (peer can't suppress)
- **Atomic congestion-controller swap** — `SetCongestionController` safe under live traffic
- **Fragment buffer caps** — `MaxGroupsPerStream=16`, `MaxStreamsInFragBuffer=1024`
- **Resume prefix collision fix** — resume wire prefixes moved to 0xFA/0xF9/0xF8 (was colliding with dialNoncePrefix=0xFD)
- **TicketStore bounded** — `DefaultTicketCacheSize=4096` with FIFO eviction, lazy-expire on lookup

Full audit trail: `docs/_SECURITY.md` + `docs/_implementation_plan.md`.

### 34.2 Retry Token Wire Format (S3)

The retry token is a QUIC-style stateless cookie that forces unverified initiators to demonstrate source-address possession before the responder commits Noise handshake state. Bound entirely to HMAC — the responder keeps no per-initiator state, so an attacker spoofing source addresses cannot exhaust responder memory.

**RETRY packet** (responder → initiator, sent in response to first-time msg1 when `RequireRetryToken=true`):

```
[retryPrefix:1 = 0xFE][nonce:8][expiryUnixSec:8][HMAC:32]   = 49 bytes total
```

**Retry-bearing msg1** (initiator → responder, on second attempt):

```
[retryPrefix:1][nonce:8][expiryUnixSec:8][HMAC:32][original-msg1...]
```

**Fields**:

| Field | Size | Notes |
|-------|------|-------|
| `retryPrefix` | 1 | Always 0xFE. Chosen to avoid collision with STUN (0x00-0x3F), QUIC (0x40-0xBF), dial-nonce prefix (0xFD), resume prefixes (0xFA/0xF9/0xF8), and Noise handshake bytes (ephemeral public key — high-entropy) |
| `nonce` | 8 | Random per-token, generated via `crypto/rand`; freshness guard |
| `expiryUnixSec` | 8 | Big-endian unix seconds when this token expires (`RetryTokenTTL = 30s` by default); short enough that attackers can't stockpile |
| `HMAC` | 32 | HMAC-SHA256 over `sourceIP ‖ nonce ‖ expiryUnixSec` keyed with the responder's per-process `secret` (random, regenerated on restart) |

**Validation** (`noise/retry.go:ValidateAndStrip`):

1. Length ≥ 49
2. Prefix byte matches 0xFE
3. HMAC verified with constant-time compare against recomputed HMAC over observed source IP + embedded nonce + embedded expiry
4. Current time < expiry
5. Strip prefix + return inner msg1 for normal Noise processing

**Policy**: `RequireRetryToken` in `NoiseTransportConfig` is a `*bool` tri-state — nil defaults to ON (security baseline), `false` disables for backward-compat with legacy initiators. An enabled responder:

1. Receives msg1 without retry prefix → replies with a RETRY packet and discards the msg1 (zero state committed)
2. Receives msg1 with retry prefix → validates + strips + processes the inner msg1

The initiator's handshake loop handles both paths transparently (`performInitiatorHandshake*` retries once on retry-prefix response). Sessions are never killed by retry round-trips; only the latency is paid.

Implementation: `noise/retry.go`, `noise/handshake.go`, `noise/transport.go:RequireRetryToken`.

### 34.3 Scope / Tenant Preamble

Multi-tenant deployments use a pre-handshake preamble to route incoming datagrams to the correct tenant's network-key material. The preamble sits BEFORE the Noise handshake — it's the first bytes the listener sees on a new source address.

**Preamble format**:

```
[magic:2 = 0x5450 "TP"][scopeIDLen:2][scopeID:N]
```

| Field | Size | Notes |
|-------|------|-------|
| `magic` | 2 | Always `0x54 0x50` (ASCII "TP" — Tenant Preamble); cheap detection test |
| `scopeIDLen` | 2 | Big-endian uint16; maximum `MaxScopeIDLength = 256` bytes |
| `scopeID` | N | Tenant identifier (opaque to aether; consumer-defined — typically hex-encoded tenant UUID) |

**Dispatch**: `noise/session.go:runReader` classifies each incoming datagram via `ClassifyPacket`:

- STUN magic (0x2112A442 cookie) → route to STUN handler
- QUIC long-header bit → route to quic-go demux
- TP magic → extract scopeID, call `TenantKeyResolver(scopeID)` to get the network key, then process as a Noise handshake
- Otherwise → treat as an in-flight Noise session packet, dispatched by source address

When no `TenantKeyResolver` is configured (single-tenant mode), the listener rejects TP-preambled packets and uses the transport's static `NetworkKeys` list. Preamble is optional — single-tenant deployments don't send one.

Implementation: `noise/preamble.go`, `noise/session.go` (`ClassifyPacket` + dispatch).

## 35. Agnostic Capability Interfaces

Sessions expose optional capabilities via interface probes so consumers don't couple to concrete adapter types. All interfaces live in the top-level `aether` package (no cycles).

### 35.1 `aether.AbuseScoreCapable`

```go
type AbuseScoreCapable interface {
    PeerAbuseScore() float64
    SetAbuseScoreRegistry(registry interface{}) bool
}
```

Shared registry enables cross-session scoring: a peer misbehaving on reconnect (closing + reopening sessions as each hits its per-session threshold) is caught when the aggregate score crosses threshold. Registry argument is `interface{}` to avoid an `abuse` → `aether` import cycle; setter returns false on type mismatch.

Implemented by: `*NoiseSession`, `*TCPSession` (and via embedding: `*WebSocketSession`, `*GrpcSession`).

### 35.2 `aether.IdleEvictable`

```go
type IdleEvictable interface {
    LastActivity() time.Time
    IdleTimeout() time.Duration
}
```

Consumers can query idle state + configured threshold without poking at adapter internals. Backed by `healthMon.LastActivity()` and `SessionOptions.SessionIdleTimeout`.

### 35.3 `aether.CompressionCapable`

```go
type CompressionCapable interface {
    CompressionEnabled() bool
    SetCompressionEnabled(bool)
}
```

Runtime-mutable via atomic.Bool. Typical callers: netmon link-change handlers flipping compression based on metered/unmetered link type; adaptive CPU controller disabling compression under load; operator overrides.

### 35.4 `aether.TicketCapable`

```go
type TicketCapable interface {
    IssueTicket(sess Connection) ([]byte, error)
    ResumeSession(ticket []byte) (Connection, error)
}
```

Marker for transports that support session-ticket issuance (§31). `NoiseTransport` implements it; other transports (QUIC/WS/gRPC) do not — QUIC has its own native resumption, byte-stream transports don't benefit from 0.5-RTT semantics.

Consumers type-assert at the transport level (not per-session) because ticket issuance is a transport-wide capability tied to the ticket-store key. `ResumeSession` is currently a stub returning an error — resume happens automatically inside `NoiseTransport.Dial` when a cached ticket is available; external callers don't invoke `ResumeSession` directly.

### 35.5 `aether.RelayCapable`

```go
type RelayCapable interface {
    SupportsRelay() bool
    RegisterExternalSession(NodeID, Connection)
    UnregisterExternalSession(NodeID)
    HandleExternalRelayFrame(sourceNodeID NodeID, data []byte) error
}
```

Marker for protocol adapters that can forward frames for external peers — i.e. act as a relay node. `NoiseTransport` implements it (UDP-native multi-tenant relay path). Byte-stream transports don't implement it; relaying through WS/TCP/gRPC is handled at a higher layer.

## 36. SessionOptions

Every adapter constructor takes `aether.SessionOptions`:

```go
type SessionOptions struct {
    FEC                  bool          // master switch; default true
    Compression          bool          // DEFLATE threshold-gated; default true
    Encryption           bool          // per-frame AEAD above Noise; default true (inert until SetSessionKey)
    Scheduler            bool          // WFQ; default true
    HeaderComp           bool          // v2 short headers; default true
    FrameLogging         bool          // default false
    MaxBandwidth         int64         // 0 = unlimited
    CongestionAlgo       string        // "cubic" (default) or "bbr"; AETHER_CONGESTION env fallback
    MaxConcurrentStreams int           // peer admission cap; 1024 Noise / 256 TCP-family default
    MaxFECGroups         int           // decoder budget; 256 default
    SessionIdleTimeout   time.Duration // idle eviction threshold; 5 min default
}
```

`aether.NormalizeSessionOptions(opts)` fills numeric / string zero-values with documented defaults; boolean fields pass through unchanged (Go zero-value ambiguity with "explicitly false"). Callers who want full feature defaults start from `aether.DefaultSessionOptions()` and override.

Unified constructor signature across every adapter:

```go
adapter.NewSessionForProtocol(conn, proto, local, remote, opts) (aether.Session, aether.Protocol, error)
```

Returns the primary protocol that won (useful for multipath `TopUpPaths` skip-list construction) plus the session.

---

*End of specification v6.1.*
