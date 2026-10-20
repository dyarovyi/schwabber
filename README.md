# Schwabber

A native Windows version lives in [`windows/`](windows/README.md).

Native macOS SwiftUI app for inspecting TCP and UDP conversations in PCAP and PCAPNG files. Requires macOS 14+ and Swift 6 (Xcode or Command Line Tools). Uses macOS's built-in libpcap; no external dependencies or network services.

```sh
swift run Schwabber
```

Open a capture with **⌘O**, filter by endpoint address or port, select a protocol, and zoom into the horizontally scrollable timeline. Each row is a bidirectional conversation; ticks show packet arrivals. Click a row to inspect packet timestamps, endpoints, original wire lengths, and TCP flags.

## Session semantics and limits

- Sessions group protocol and unordered IP/port endpoint pairs, splitting after more than 60 seconds without traffic. This is a conversation heuristic, not TCP connection-state reconstruction; rapid port reuse can merge separate connections.
- Timeline timestamps are relative to the first supported packet. Packets are sorted by capture timestamp.
- Ethernet (including VLAN), loopback, raw IP, and Linux cooked capture links are supported, with IPv4 and IPv6 TCP/UDP decoding.
- Non-initial IP fragments, other protocols, and truncated/unsupported headers are counted as skipped. No fragment or stream reassembly, tunnel decoding, or encrypted DNS decoding yet.
- All supported packet metadata and original packet bytes are held in memory for export. The inspector and timeline include all supported packets. Very large captures may consume substantial memory.
- Imports run in the background. Files stay local.

## Development

```sh
swift build
swift test
```

Open `Package.swift` in Xcode to develop and run the app.

## Build a macOS app bundle

```sh
./scripts/build-app.sh
open dist/Schwabber.app
```

You can also double-click `dist/Schwabber.app` in Finder or copy it to Applications. The script builds an optimized release executable for the current Mac architecture, creates the bundle metadata, and applies an ad-hoc signature for local use. Distribution to other Macs requires Developer ID signing and notarization.

### Validation on this machine

`swift build` succeeds. Eleven core checks passed using the standalone Swift harness (see Additional verification below). `swift test` requires XCTest, which is absent from this machine's Command Line Tools installation; select a full Xcode installation to use the standard test runner. The GUI has not yet been visually verified.

## DNS inspection

DNS on port 53 is decoded over UDP and for complete length-prefixed messages within a TCP packet. DNS conversations appear purple; the DNS filter includes both transports, and the UDP filter still includes DNS over UDP. Search includes DNS questions and answers. Hover over the Protocol details cell to read the full summary.

Details include transaction ID, query/response, question names/types, response code, truncation flag, and A, AAAA, CNAME, NS, PTR, and MX answers. Other answer types show their type and data length. Malformed or incomplete DNS remains visible as ordinary transport traffic. DNS transactions remain in their endpoint session rather than becoming separate rows. TCP messages spanning packets, IP fragment reassembly, mDNS, DoH, and DoT are not decoded.

DNS wire-format reference: [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035).

## Higher-level protocols

The protocol picker, session labels, timeline colors, search, and packet inspector now include:

| Protocol | Visible details |
| --- | --- |
| STUN | Method/class, transaction ID, IPv4 XOR-MAPPED-ADDRESS when present |
| HTTP | HTTP/1 request/status line and Host header; HTTP/2 client preface identification |
| TLS | First record type, record-layer version, size, handshake type; SNI and ALPN from a complete ClientHello |
| QUIC | Recognized v1/v2 long-header type, version, destination/source connection IDs |

Detection uses payload structure rather than port numbers. These are packet-local decoders, not complete stream dissectors: TCP reassembly, HTTP bodies, HTTP/2 frames, QUIC decryption, short-header-only QUIC detection, and TLS decryption are not implemented. TLS record versions are legacy framing values, not the negotiated TLS version. Encrypted HTTPS is labeled TLS unless readable HTTP is present. QUIC labels describe visible headers, not authenticated/decrypted contents. A session shows all protocols detected in its packets.

Wire-format references: [STUN](https://www.rfc-editor.org/rfc/rfc8489), [HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112), [TLS](https://www.rfc-editor.org/rfc/rfc8446), [QUIC](https://www.rfc-editor.org/rfc/rfc9000).

## Open sessions in Wireshark

Use row checkboxes or **⌘-click** to select multiple sessions, **Shift-click** for a visible range, or **Select shown** for the current filter. A normal click selects and inspects one session. Selected sessions remain selected when filters change; the selection count includes hidden selections. **Clear** removes all selections.

Click **Open in Wireshark**. The app exports both directions of the selected sessions into one new PCAP, in original capture order, then opens it in the installed Wireshark app. Original packet bytes, captured/wire lengths, and microsecond timestamps are preserved. The source capture is unchanged. PCAPNG comments/interface metadata and sub-microsecond precision are not retained. Only packets represented by selected sessions are exported; skipped packets and non-initial fragments are excluded.

Exports are retained under `Schwabber-Exports` in the macOS temporary directory so Wireshark can continue reading them. Use Save As in Wireshark to keep a permanent copy. Wireshark must be installed separately.

### Additional verification

`python3 scripts/check-core.py` runs the core test methods through a standalone assertion harness on machines without XCTest. Eleven checks cover protocol decoding, TLS SNI/ALPN, malformed/truncated input, session grouping, and single/multiple-session export round-trips. The release bundle builds and its local signature verifies. UI click verification requires Computer Use permissions, which were unavailable in this session.

A synthetic four-session capture was decoded as HTTP, STUN, TLS, and QUIC. Exporting only its HTTP and STUN sessions produced a two-packet file that Wireshark’s `tshark` read successfully with the expected protocols and timestamps.

## Session sizes and saving a selection

Click a session to see its total size in **bytes and decimal kilobytes** (1 kB = 1,000 bytes) above the packet inspector. The selection toolbar also shows the combined size of all selected sessions, including selections hidden by filters. Sizes sum original packet lengths in both directions, including packet headers; they are not application-payload sizes or PCAP file sizes.

Select sessions with checkboxes, ⌘-click, Shift-click, or **Select shown**, then click **Export selected…**. Choose a filename and folder in the Save dialog to write a separate `.pcap` without opening Wireshark. Export uses the same packet-preserving writer as the Wireshark action; its format limits described above still apply. The app confirms the saved path after export; cancellation writes nothing.

## App icon

The mop icon is stored in `Assets/Schwabber-icon.png`, with the macOS icon in `Assets/Schwabber.icns`. `scripts/build-app.sh` regenerates the icon sizes and embeds the icon in the app bundle. Generation details are recorded in `Assets/icon-prompt.md`.

## Packet popup inspector

Click a session, then a packet row to open a separate resizable inspector window. Like the Windows version, it has two panes: expandable protocol fields and interactive hex/ASCII bytes. Click a field to highlight its bytes; click a byte to select its most specific field. Hover over bytes for field details. Headers are shaded. Field selection and tree expansion are remembered while navigating packets.

Previous/Next buttons, ⌘← / ⌘→, Option← / Option→, or Page Up / Page Down navigate within the session and update the main packet selection. The popup reuses one window.

**Include headers** switches between the captured frame and TCP/UDP payload and hides/shows link/network/transport fields. Application headers remain in the payload. Three size cards show sizes with headers, without headers, and header components, distinguishing captured bytes from on-wire lengths. Truncated captures are marked. Payload offsets start at zero when headers are hidden. The Text toggle shows UTF-8 with replacement characters for invalid bytes.

The built-in analyzer works without Wireshark and decodes Ethernet/VLAN, IPv4/IPv6, TCP (including options), UDP, HTTP, DNS, TLS, STUN, and QUIC fields. These are packet-local decoders; encrypted content and messages split across packets require additional analysis.

Enable **Wireshark analysis** for Wireshark’s decoded field tree and reassembled/decrypted data sources. Installed `tshark` analyzes the original full capture in two passes with reassembly enabled and name resolution disabled. Keep the source file available and unchanged. The **Data source** picker lists extra sources when Wireshark produces them for the selected frame. Reassembly may belong to the final segment. Extra sources are displayed intact; the header toggle affects captured frame bytes. Field-to-byte selection is available in the built-in view, not the optional Wireshark tree or generated sources.

Use **Choose TLS key log…** to supply a compatible NSS/SSLKEYLOGFILE-format secrets file. Decryption requires matching secrets, sufficient capture context, and protocol support in the installed Wireshark. No keys are derived or fetched. Temporary analysis output is deleted after use. Analysis is cancelled when switching packets and times out after 120 seconds per pass.

Validation: eleven core checks cover decoding, payload boundaries, field-to-byte lookup, TCP options, HTTP/DNS/TLS fields, truncated input, export, PDML parsing, and multi-source byte parsing. A `tshark` integration check verified an HTTP request split across two TCP packets. TLS decryption and GUI interactions have not been end-to-end verified.

## Timeline and opening captures

Session labels stay pinned on the left when scrolling horizontally. Their colored fill and percentage show the session's share of all on-wire bytes in the capture, including unsupported packets; filtering does not change that denominator. Hover for exact bytes and percentage. Time labels and grid lines use round 1/2/5 steps that adapt to zoom. Click or drag the zoom track to choose a level.

The selected session's protocol summary appears above its packet list. Opening another capture closes the previous packet window.

Open captures from Finder using **Open With → Schwabber**, drag a capture onto the app or its window, or run `swift run Schwabber /path/to/capture.pcap`. The bundle declares PCAP, PCAPNG, CAP, and DMP document types without taking over the default file association.

The native packet tree also decodes DNS MX/TXT records, TLS supported versions/groups and named cipher suites, and STUN address/text/error attributes. These remain packet-local details; the optional Wireshark mode provides reassembly/decryption when available. No theme picker was added.

## RTP and STUN (macOS and Windows)

Both apps include RTP and STUN in protocol filters, session summaries, search, and packet details. RTP over UDP is detected heuristically from its version-2 header, CSRC count, extension length, and padding. Packet details expose marker/payload type, sequence, timestamp, SSRC, CSRCs, raw extension data, media bytes, and padding. The RTP/RTCP multiplexing reserved payload-type range (64–95) is excluded to avoid labeling RTCP as RTP. False positives remain possible without signaling context.

Dynamic payload types remain numeric: there is no SDP codec mapping, audio/video playback, loss/jitter analysis, RTP-over-TCP framing, or SRTP decryption. Session grouping remains based on endpoint pairs, so multiplexed STUN/RTP can share a session. The header toggle continues to control link/IP/transport headers, retaining RTP headers in the UDP payload. RTP layout follows [RFC 3550](https://www.rfc-editor.org/rfc/rfc3550.html).

STUN recognition validates the magic cookie and message/attribute lengths and exposes transaction IDs and attributes. TURN method summaries include Allocate, Refresh, Send, Data, CreatePermission, and ChannelBind. TURN ChannelData is described below; encapsulated media is retained as raw channel bytes.

## Real-time communication protocols (both platforms)

RTCP, SIP, DTLS, and TURN appear in the protocol picker, session labels, search, and packet details with byte-linked fields.

- **RTCP:** compound packet framing and sender/receiver reports, including SSRCs, sender counts, signed cumulative loss, fraction lost, extended sequence, jitter in RTP timestamp units, LSR and DLSR. Other report types retain raw report data. RTT is not calculated and jitter is not converted to milliseconds without a clock rate. [RFC 3550](https://www.rfc-editor.org/rfc/rfc3550.html).
- **SIP/SDP:** request/status lines, headers, Call-ID, and SDP body lines including media endpoints and `rtpmap` codec mappings. SDP is shown inside SIP, not as a separate protocol filter. Parsing is packet-local; there is no TCP message reassembly, offer/answer correlation, or automatic codec assignment to RTP sessions. [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261.html).
- **DTLS:** DTLS 1.0/1.2 record headers, epoch, sequence, and plaintext handshake fragment headers. Fragment bytes remain raw: certificates, hello extensions, and SRTP negotiation are not decoded; DTLS 1.3 unified records and decryption are not supported. [RFC 6347](https://www.rfc-editor.org/rfc/rfc6347.html).
- **TURN:** heuristic identification of a complete ChannelData message, channel number, length, raw relayed bytes and padding. TCP requires complete padded framing within one packet; multiple ChannelData messages and stream reassembly are not supported. [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766.html).

Validation: 13 macOS core checks pass, including compound RTCP, signed loss, DTLS fragments, SDP, TURN padding, byte bounds, and truncated input. The release bundle builds and its signature verifies. The matching Windows tests pass. GUI interactions remain visually unverified.

## ICMP and HTTP

Both platforms now include ICMPv4 and ICMPv6 in the timeline, protocol filters, exports and packet inspector. Echo identifier/sequence, type/code, checksum and MTU fields are displayed. Other message-specific content and quoted packets remain raw; checksums are not verified. Conversations group by IP endpoint pair and the existing 60-second idle timeout, so concurrent ping identifiers can share a row. Headers excluded means the first eight ICMP bytes are excluded along with link/IP headers. See [ICMP](https://www.rfc-editor.org/rfc/rfc792) and [ICMPv6](https://www.rfc-editor.org/rfc/rfc4443.html).

HTTP support already includes HTTP/1.x requests/responses and headers, plus HTTP/2 connection-preface recognition. Native HTTP/2 frame decoding and HTTPS decryption are not included; optional Wireshark analysis can provide additional decoding.

## Live recording

Choose an interface, click **Start recording**, and watch sessions update approximately twice per second. **Stop recording** finishes the file; **Save recording…** saves the complete PCAP, including unsupported packets. This differs from **Export selected**, which saves only selected sessions. The interface and Open command are locked during recording. Capture-buffer drop counts are displayed. Captures use a 262,144-byte snapshot length, non-promiscuous mode, and no capture filter.

macOS uses built-in libpcap and needs permission to open `/dev/bpf` devices (for example, Wireshark’s ChmodBPF installation). Windows requires [Npcap](https://npcap.com/guide/npcap-users-guide.html); it lists adapters at startup and picks a connected one, and **Capture → Refresh interfaces** enumerates them again. Offline file analysis still works without Npcap. Capture permission errors are reported without changing system permissions.

Recordings are retained in `Schwabber-Recordings` beneath the operating system’s temporary directory, including after canceling Save or starting another recording. Save important recordings permanently before temporary-file cleanup. Supported packet bytes remain in memory for the timeline, so large recordings require sufficient memory and disk space. The inspector is a snapshot of the session when opened; reopen it for newer packets. Stopping ends at the packets already read, rather than draining all queued adapter traffic.

Windows live capture was verified with Npcap on a Wi-Fi adapter: sessions updated while recording, and Stop closed a valid PCAP.

## Compact macOS layout

The session column stays outside the horizontally scrolling timeline. Drag its vertical divider to adjust width; both columns share vertical scrolling. The packet footer keeps its resizable horizontal divider. Opening a different capture resets the split layout and fits the timeline at 1× zoom.

Secondary controls are in the menu bar: **File** contains Open, Export selected sessions, and Open selected in Wireshark; **Sessions** contains Select shown and Clear selection; **Capture** contains the interface picker, refresh, Start/Stop, and Save recording. The compact top area retains filters, zoom, counts and a Stop button while recording.

## macOS performance

Timeline rendering is limited to the visible session rows plus a small scrolling buffer, including the horizontally scrollable graphs. Session byte totals and protocol summaries are maintained incrementally. Search short-circuits without constructing a concatenated string of every packet's details. Idle live captures no longer publish unchanged snapshots, and opening another file releases the previous recording's in-memory snapshot (its temporary PCAP remains available). Full packet bytes are still retained for inspection/export, so memory continues to grow with capture size.

A synthetic 29,000-packet/200-session core benchmark showed roughly 7× faster repeated metadata access after caching. This benchmark excludes SwiftUI rendering and does not establish the full app's memory use or reproduce the reported 700 MB case.

## Session actions and filters (macOS)

After stopping a recording, use **File → Save PCAP…** (⌘S). Right-click a session label or timeline to inspect it, open that session in Wireshark, export it, or change selection. Explicit session actions target the clicked row; selected-session actions target the checked rows.

The Protocols menu offers **All** or multiple individual checkboxes. Selected protocols combine with OR; transport filters such as UDP include application protocols carried over UDP. With no boxes checked, no sessions are shown.

Search matches addresses, ports and protocol details case-insensitively, or exact case-sensitive UTF-8 text in individual packet payloads. Use `x00x01xFF` for hexadecimal payload bytes. Invalid hex patterns are indicated. Payload searches exclude link/network/transport headers and do not reassemble messages or decrypt content. Filtering resets scrolling to the top; the list height and visible-row range are bounded by its filtered contents.

## HTTP/2 and TCP-stream reassembly (macOS)

HTTP/2 now has a protocol filter and native fields for frame length/type, flags, stream IDs, SETTINGS, WINDOW_UPDATE, RST_STREAM and GOAWAY. Complete packet-local frame sequences are recognized heuristically; the connection preface provides stronger identification. HEADERS/PUSH_PROMISE/CONTINUATION payloads remain raw HPACK blocks. This is not a full connection-state/HPACK implementation, and encrypted HTTP/2 remains TLS without decryption. Frame definitions follow [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html).

Right-click a TCP or TLS session and choose **Reassemble TCP stream…**. No Wireshark installation or TLS keys are needed. Choose a direction and contiguous chunk, inspect hex or a bounded text preview, and save the chunk as binary. TCP sequence numbers determine ordering; retransmitted overlap is removed and conflicts counted. Missing byte ranges remain separate chunks rather than being filled or silently concatenated. TLS bytes remain encrypted. The view is a snapshot, not a live-updating stream.

Offsets are relative to the first captured data byte; missing prefixes/suffixes cannot be inferred. Reassembly inherits the endpoint/idle-time session grouping, so reused connections can be merged. Sequence-space spans of 2 GiB or more are unsupported. For conflicting overlaps the first segment in sequence-order wins (capture ID breaks ties). Checksums are not verified. Windows has the same HTTP/2 decoding and Reassemble TCP stream window.

Validation: 18 core checks pass, including HTTP/2 control frames, malformed lengths, native fields, out-of-order segments, retransmission, gaps, and sequence wraparound. Release build and signature verification passed; the new window still needs visual verification.

### Wireshark data sources in the macOS packet inspector

The inspector enables Wireshark analysis by default and uses the `sharkd` executable shipped with Wireshark. The Data source picker lists the actual sources produced for the selected frame, including decrypted QUIC and reassembled TCP/TLS when available. Choose a TLS key log for encrypted application traffic; sources that Wireshark cannot reconstruct are not fabricated. Reassembly may be attached to the final contributing frame.

Both hexadecimal bytes and the ASCII column support clicking to select the most specific decoded field. Clicking a field switches to its data source and highlights its byte range. Generated fields have no byte highlight. The Include headers switch affects captured-frame bytes only. Previous/Next reanalyzes the selected packet and clears stale selections. If Wireshark is unavailable, the built-in captured-frame inspector remains usable.

### macOS navigation, pins and copying

- Up/Down select the previous/next visible session; Shift extends selection. Home/End jump to the first/last session. The list scrolls to keep the selected row visible; text fields and packet tables keep their own key handling.
- Click the time ruler or empty timeline space to pin a time across all sessions. Packet marks still open the packet inspector. Maximum zoom shows two seconds across the visible timeline; the left end of the slider fits the capture (with at least a two-second time span). Right-click a pin to remove it, or use View → Clear timeline pins. Pins reset when another capture is opened.
- View → Show endpoints toggles compact, single-line session rows. This preference persists across launches. The full endpoints remain in selected-session details.
- Dragging a capture onto the window displays a drop target. A running recording must be stopped before opening another capture.
- Right-click inspector fields to copy their label, value or bytes. Drag-select hex/ASCII bytes and copy spaced hex, a continuous hex stream, text or a hex dump. ⌘C copies selected bytes as hex; copying a focused field list copies its selected label. Byte copying also works in the reassembled TCP window.
- Help → Schwabber Help (F1) and Keyboard shortcuts provide an in-app guide. About Schwabber is in the standard application menu.
- Interface selection prefers an active non-loopback interface with addresses when no previously selected interface is available.

### Packet chunks and inspector tracking (macOS)

Nearby packet marks (less than four pixels between starts) merge into chunks at the current zoom. Clicking a chunk opens its first packet; zooming or resizing recomputes the grouping. The inspector header shows the packet's session position, position within a multi-packet chunk, and arrival time relative to the capture start. Its packet is marked on the timeline and revealed vertically and horizontally when navigating; closing the inspector removes the marker. Hover a pin on a session row to see its exact time. The ruler skips overlapping end labels.
