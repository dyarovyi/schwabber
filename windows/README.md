# Schwabber for Windows

Native Windows (WPF, .NET 8) version of Schwabber. It has the same features as the macOS app; see [Feature parity with macOS](#feature-parity-with-macos). Session semantics, decoder behavior and export format are line-for-line ports of `Sources/CaptureCore`, so the main [README](../README.md) applies; Windows-specific differences are listed below.

Requires Windows 10 or 11. Building requires the .NET 8 SDK; running a framework-dependent build requires the .NET 8 Desktop Runtime.

```powershell
dotnet run --project windows\Schwabber
```

## Build an executable

```powershell
powershell -ExecutionPolicy Bypass -File windows\scripts\build-app.ps1
dist\Schwabber\Schwabber.exe
```

This produces a single `Schwabber.exe` (about 1 MB) that needs the .NET 8 Desktop Runtime. Add `-SelfContained` to bundle the runtime for sharing with PCs that don't have it. That build goes to `dist\Schwabber-win-x64` as one compressed file of about 65 MB that runs on any 64-bit Windows 10 or 11 PC. Add `-Runtime win-arm64` for ARM devices. The build is unsigned; SmartScreen may warn on other PCs until it is signed with a code-signing certificate.

You can also pass a capture path on the command line, use **Open with → Schwabber** in Explorer, or drag a file onto `Schwabber.exe`.

## Development

```powershell
dotnet build windows\Schwabber.Windows.sln
dotnet test windows\Schwabber.Windows.sln
```

`CaptureCore.Tests` contains ports of the macOS core checks (decoding, grouping, export, DNS, RTP/STUN, realtime protocols, ICMP, HTTP/2, TCP reassembly, payload filtering and Wireshark data-source parsing), Windows-only tests for PCAPNG, nanosecond PCAP and truncated files, dissector tests that check every byte maps to a field, and a live `sharkd` check that runs when Wireshark is installed.

## Feature parity with macOS

The Windows app follows the macOS layout and behavior described in the main [README](../README.md). In short:

- **Window and menus.** A compact window with the Schwabber wordmark grows to 1300 × 850 once a capture or recording is open. The **File** menu has Open capture (Ctrl+O), Save PCAP (Ctrl+S, for recordings), Export selected sessions and Open selected in Wireshark. The **Sessions** menu has Select shown and Clear selection, and the **Capture** menu has the interface list, Refresh interfaces, and Start and Stop recording. Drop a capture onto the window, including the welcome screen, to open it. A dashed outline names the file while you drag it.
- **Filtering and sorting.** Search matches addresses, ports and protocol details, or exact text in packet payloads. Hex patterns such as `x00x01xFF` also work, and invalid hex is flagged. The **Protocols** popup combines any of 15 protocols with OR, and **Sort** offers Chronological or Largest first.
- **Timeline.** The session column stays pinned while scrolling, and you can drag its divider to resize it. Each row shows its share of all capture bytes. Time labels adapt to zoom. Clicking a packet tick opens that packet. Right-click a session to reassemble its TCP stream, inspect it, copy its 5-tuple, open or export it, or change the selection.
- **Inspector.** The split between the timeline and the inspector can be resized. The packet list includes every packet in the session, with a **Delta time** column.
- **Packet inspector window.** **Wireshark analysis**, on by default, uses `sharkd` from the installed Wireshark for its field tree and for reassembled or decrypted **data sources**. **Choose TLS key log…** takes an SSLKEYLOGFILE secrets file. Without Wireshark, the built-in analyzer and byte-to-field selection still work. The window also has **Include headers**, **ASCII only**, size cards, and Previous/Next (Ctrl+←/→, Alt+←/→ or Page Up/Down).
- **Help (Windows addition).** **Help → Schwabber Help** (F1, also in the packet inspector) opens a built-in user guide with a table of contents. It covers opening captures, the timeline, filters, selection, export, pins, both inspectors, Wireshark analysis and TLS keys, copying, TCP stream reassembly, live recording, view options, protocols, keyboard shortcuts, and limits. **Help → Keyboard shortcuts** jumps to the shortcut table, and **Help → About Schwabber** shows the version.
- **Timeline pins, zoom and view options (as on macOS).** Click the time ruler or empty timeline space to pin that moment. The pin is a dashed orange line across every session, for comparing sessions at the same instant. Hover its marker for the exact time, or right-click it to remove it. **Clear all pins** is on the ruler's right-click menu, and **View → Clear timeline pins** does the same. Pins are cleared when another capture opens. The zoom slider is logarithmic: left fits the capture, and right shows two seconds across the visible timeline, which always spans at least two seconds. Scroll the timeline sideways with a two-finger horizontal touchpad swipe, Shift+mouse wheel or a tilt wheel. **View → Show endpoints**, on by default and remembered, shows or hides the address:port line. Hiding it shrinks rows from 36 to 23 px. The session number sits next to its checkbox.
- **Inspected packet on the timeline (Windows addition).** The packet open in the packet inspector is marked in its session row with a bright tick and triangle. The timeline scrolls to it if needed, and the marker follows Previous/Next. The inspector header shows the packet's exact arrival time relative to the capture start, after its number and position. Packets too close to tell apart at the current zoom are drawn as one chunk; clicking it opens the chunk's first packet, and the inspector shows "N of M in chunk" next to the session position.
- **Keyboard and copying (Windows additions).** In the timeline, Up and Down move between sessions and inspect them. Shift extends the selection, and Home and End jump to the first and last session. In the packet inspector, Ctrl+C copies the selected field. Right-click a field to copy the line, its value, or its bytes as hex or text. Drag across the bytes pane to select a range, then copy it with Ctrl+C or right-click as hex, a hex stream, text or a hex dump. Ctrl+A selects every byte shown.
- **Reassembled TCP stream window.** It shows each direction's contiguous chunks with missing, overlapping and conflicting byte counts, a hex or text preview, and **Save chunk…**.
- **Protocols.** It decodes TCP, UDP, ICMP and ICMPv6, DNS, RTP, RTCP, SIP/SDP, DTLS, TURN, STUN, HTTP, HTTP/2 frames, TLS and QUIC, as on macOS.
- **Live recording.** See [Live recording](#live-recording).

## Shared timeline behavior (ported to macOS)

The following behavior is implemented on both platforms. Windows references are retained here; macOS uses `TimelineChunks.swift`, `TimelineInspection.swift`, and its native packet inspector.

### Packet chunks on the timeline

Packets too close to tell apart at the current zoom are drawn as one **chunk**, and chunks are recomputed whenever the zoom or the timeline width changes (`TimelineChunks` in `Schwabber/Controls.cs`).

- **Position.** A packet's x is `min(width − 2, (time − captureStart) / duration × width)`, where `width` is the full (zoomed) timeline width. A tick is 2 px wide.
- **Grouping.** Walk the session's packets in order. A packet joins the current chunk if its x is less than **4 px** after the previous packet's x; otherwise it starts a new chunk. Because each packet is compared with the one before it, a dense run chains into one chunk however long it is. This replaces the previous rule, which drew only the first packet in each pixel.
- **Drawing.** Each chunk is one filled rectangle from its first packet's x to its last packet's x + 2 px, in the session accent color and at full tick height. A single-packet chunk looks exactly like a normal tick. The inspected-packet marker is still drawn at the packet's own x.
- **Clicking.** Hit-testing uses the same chunks: the nearest chunk whose span is within 3 px of the pointer, inside the tick band. Clicking a chunk opens the packet inspector on the chunk's **first** packet (`OnRowClick` in `MainWindow.xaml.cs`).
- **Inspector header.** The position text now reads `Packet #<id> · <i> of <n> in session`. When the packet is in a chunk of two or more at the current zoom, it continues with ` · <j> of <m> in chunk`, for example `Packet #812 · 34 of 1,200 in session · 1 of 7 in chunk`. It updates on Previous/Next and when the zoom changes while the inspector is open (`PacketWindow.UpdatePosition`, `MainWindow.ChunkOf`).

### Inspected packet on the timeline

- The packet open in the packet inspector is marked in its session row: a soft glow across the full row height (text color at 22% opacity, 8 px wide), a solid 3 px bar in the text color, and a 10 × 6 px downward triangle at the top (`TimelineBar.DrawHighlight`). The marker disappears when the inspector closes.
- When the inspected packet changes, the timeline scrolls vertically to its session row and horizontally to center the packet if it is off-screen or within 20 px of either visible edge (`RevealPacket`).
- The inspector header shows the arrival time relative to the capture start, `+0.400000 s` (6 decimals), after the position text.

### Other Windows additions

These are described under [Feature parity with macOS](#feature-parity-with-macos): the built-in Help window, keyboard session navigation (Up/Down, Shift, Home/End), and copying fields and byte ranges in the packet inspector.

## Differences from the macOS app

- **No libpcap/Npcap dependency for offline reading.** Captures are read by a built-in managed PCAP/PCAPNG reader that mirrors libpcap's behavior: microsecond timestamps (nanosecond files are truncated to microseconds), the first interface's link type for PCAPNG, and errors for truncated files or PCAPNG interfaces with differing link types. Classic PCAP in either byte order, nanosecond PCAP, and the modified (Kuznetzov) PCAP format are supported.
- **Shortcuts.** Ctrl replaces ⌘: Ctrl+O, Ctrl+S, Ctrl-click to add a session to the selection, and Ctrl+←/→ in the packet inspector.
- **Wireshark.** The app finds `Wireshark.exe` and `sharkd.exe` through Wireshark's registered App Path, then in `Program Files\Wireshark`. Temporary exports go to `%TEMP%\Schwabber-Exports`.
- **Appearance.** **View → Theme** offers System theme, Light and Dark; macOS follows the system appearance only. System theme follows the Windows app setting, including changes made while the app is open, and the choice is saved in `%LOCALAPPDATA%\Schwabber\theme.txt`. Other preferences, currently Show endpoints, are stored in `settings.txt` in the same folder. Protocol colors use the macOS light or dark variants. Message boxes and file dialogs are drawn by Windows and follow its own setting.
- **Time axis labels.** Both platforms skip a final label that would overlap its neighbour.
- **Icon.** `windows\Schwabber\Schwabber.ico` is generated from `Assets/Schwabber-icon.png` by `windows\scripts\build-icon.ps1`, which `build-app.ps1` runs automatically.

### Validation on this machine

All 24 core tests pass, including a real `sharkd` analysis. The GUI was checked with screenshots in dark and light themes:
- the empty state and loaded timeline
- the Protocols popup and session context menu
- the Reassembled TCP window
- the packet inspector with Wireshark analysis, where clicking SNI bytes selected Wireshark's Server Name field
- live recording on a Wi-Fi adapter with Npcap

A 300,000-packet capture loaded earlier in about one second of parsing. The **Open in Wireshark** launch and TLS decryption with a real key log were not exercised.

## Live recording

Live recording needs [Npcap](https://npcap.com/). At startup the app lists adapters and selects a connected one with an address. Pick another under **Capture → Interface** or in the empty-state picker, then click **Record PCAP** or **Capture → Start recording**. Sessions update about twice a second, and the header shows the number of dropped packets. Click **Stop**, then **File → Save PCAP…** (Ctrl+S) to save all captured traffic. Closing the window during a recording finishes the file first. Without Npcap, offline files still open, and the empty state says that recording needs Npcap. See the main [live recording documentation](../README.md#live-recording) for storage, limits and permissions.
