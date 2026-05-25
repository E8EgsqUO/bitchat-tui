# bitchat-tui

`bitchat-tui` is a terminal client for BitChat. It supports the Bluetooth mesh flow and the newer Nostr geohash channels, so you can keep chatting even when mesh discovery is unstable.

## What It Does

- Bluetooth mesh chat with public rooms, channels, and direct messages
- Nostr geohash channels such as `#ws`
- Direct messages in both mesh and geohash modes
- Unread counters in the sidebar for channels and people
- Message fragmentation and reassembly for larger payloads
- TUI-to-TUI Bluetooth mesh file transfer up to 1 MiB
- Geohash DM file pairing via Magic Wormhole
- Windows, Linux, and macOS builds with the same Rust codebase
- Graceful fallback when Bluetooth mesh discovery fails, with geohash chat still available

## Requirements

- Rust toolchain
- A Bluetooth adapter for mesh mode
- On Windows, the Microsoft C++ Build Tools if `link.exe` is missing

## Install

### From Source

```bash
git clone https://github.com/E8EgsqUO/bitchat-tui.git
cd bitchat-tui
cargo run --release
```

To build only:

```bash
cargo build --release
```

### On Windows

If you want to compile directly on Windows:

```powershell
git clone https://github.com/E8EgsqUO/bitchat-tui.git
cd bitchat-tui
cargo run --release
```

If Cargo reports that `link.exe` is missing, install Visual Studio Build Tools and select `Desktop development with C++`.

## First Run

Start the app:

```bash
cargo run --release
```

What happens next:

1. The app starts scanning for the BitChat Bluetooth service.
2. If mesh is available, it connects automatically.
3. If mesh is not available, you can still join a Nostr geohash channel such as `#ws`.

If the Bluetooth mesh connection stalls or drops, press `r` on the error screen to retry the scan.

## How To Use

### Public Mesh Chat

- Type a message and press `Enter` to send to the current room.
- Use `/public` to return to the public chat.
- Use `/j #channel` to join a channel.
- Use `/leave` to leave the current channel.

### Nostr Geohash Chat

- Join a geohash channel with `/j #ws`.
- Once inside a geohash channel, the header and People section show the recent active count for that region when presence events are visible.
- Direct messages work from the `People` list in the geohash view.
- Use `/leave` to leave the geohash channel and return to public chat.
- `/w`, `/online`, `/channels`, `/name`, and `/public` work in geohash mode.
- The active count follows the BitChat geohash presence heartbeat (`kind 20001`) and counts unique pubkeys seen in the last five minutes. Presence-only users are not added to the DM People list until they send a chat message or DM.
- `/reply` is mesh-only. `/block` and `/unblock` are only available in Nostr geohash channels.

### Direct Messages

- Use `/dm <name>` to open a direct message.
- Use `/dm <name> <message>` to send a direct message immediately.
- In a geohash channel, `/dm` uses the people seen in that region. Geohash identities are per-channel Nostr keys, so arbitrary global npub values are not valid targets unless that exact key has already appeared in the current `People` list.
- Use `/w` or `/online` in a geohash channel to show seen names and their short geohash DM keys.
- In mesh mode, `/dm` uses visible Bluetooth mesh peers.
- In the sidebar, select a person to open or continue a DM.
- Unread DM counts appear next to names in `People`.

### File Transfer

- Mesh transfer stays the same: use `/file <path>` in the current room, or `/file @user <path>` for a visible mesh peer.
- In a geohash DM, use `/file <path>` to send a Wormhole offer to the current DM. From a geohash channel, use `/file @user <path>`.
- The receiver opens the same geohash DM and types `/receive` to accept the transfer.
- The sender does not enter the Wormhole code manually.
- Files are limited to 1 MiB on mesh transfer and are saved under `received_files/` on the receiving side.
- `/upload <path>` uploads media files (image/audio/video) to a configurable endpoint and sends the returned URL as a normal Nostr/geohash chat message.
- Dragging a local file into the terminal input box auto-fills `/file <path>` in mesh, or `/upload <path>` in a geohash conversation.
- This is a TUI-only extension. iOS mesh clients still use their native image and voice-note transfers.
- `/pass` has been removed from this fork.

### Image Preview

- Click an image message (local `[image] <path>` content) to open an in-TUI preview overlay.
- Press `Esc` or click inside the preview area to close it.
- Set `BITCHAT_IMAGE_PROTOCOL` to force preview protocol:
  - `auto` (default)
  - `kitty`
  - `sixel`
  - `iterm2`
  - `halfblocks`
- On Windows Terminal, `sixel` is usually the best choice:
  - PowerShell: `$env:BITCHAT_IMAGE_PROTOCOL="sixel"`
- Optional remote-image fetch tuning:
  - `BITCHAT_REMOTE_IMAGE_TIMEOUT_SECS` (default `12`)
  - `BITCHAT_REMOTE_IMAGE_MAX_BYTES` (default `20971520`, 20 MiB)

## Proxy Support

Nostr geohash channels can go through a proxy. This is useful when direct relay access is blocked or when you want to route relay traffic through a local proxy.

Set one of these environment variables:

- `BITCHAT_TUI_NOSTR_PROXY`
- `HTTPS_PROXY`
- `https_proxy`
- `HTTP_PROXY`
- `http_proxy`
- `ALL_PROXY`
- `all_proxy`

Supported proxy formats:

- `http://host:port`
- `socks5://host:port`
- `socks5h://host:port`

`https://` proxy URLs are not supported. Use `http://` or `socks5://` instead.

## Commands

- `/help` show the command list
- `/name <name>` change nickname
- `/status` show connection and session status
- `/clear` clear the current conversation
- `/r` restart Bluetooth mesh scanning
- `/exit` quit
- `/public` switch to public chat
- `/dm <name> [msg]` open a DM or send an initial message
- `/file [@user] <path>` send a file over Bluetooth mesh, or create a Wormhole offer in a geohash DM
- `/upload <path>` upload a media file (image/audio/video) and share the URL in a geohash conversation
- `/receive` accept the pending geohash DM file offer
- `/reply` reply to the last private sender
- `/j #channel` join a channel
- `/leave` leave the current channel
- `/channels` list discovered channels
- `/w` or `/online` show active geohash count and visible users
- `/block @user` block a user
- `/block` list blocked users
- `/unblock @user` unblock a user

## Sidebar Notes

- `Public` is the shared room.
- `Channels` contains joined or discovered channels.
- `People` shows nearby mesh peers or the people seen in the current geohash channel. In geohash mode, its heading can also show the recent active count from Nostr presence events.
- Unread counts are shown in parentheses when there are pending messages.

## Logging

The app can write debug logs in the project directory, including:

- `debug.log`
- `nostr_debug.log`
- `packet_debug.log`
- `send_debug.log`
- `crash.log`

File logging is off by default. To enable it for troubleshooting, set:

```bash
BITCHAT_TUI_FILE_LOG=1
```

To force-disable file logging, set:

```bash
BITCHAT_TUI_FILE_LOG=0
```

`BITCHAT_TUI_FILE_LOG` only controls whether log files are written to disk.

To enable verbose runtime/system debug messages in the TUI, set:

```bash
BITCHAT_DEBUG=1
```

`BITCHAT_DEBUG` is enabled for any non-empty value except `0`, `false`, `off`, or `no`.
`BITCHT_DEBUG` (missing `A`) is not recognized.

## Notes

- Mesh mode and geohash mode are both supported, but they are different transports.
- If Bluetooth mesh is unavailable, geohash channels remain usable.
- `r` is still useful as a recovery action when the Bluetooth scan needs to be restarted.
- Proxy settings apply to Nostr relay traffic, not Bluetooth mesh traffic.
- `/upload` is a Nostr/geohash feature and also uses proxy env vars (`BITCHAT_TUI_NOSTR_PROXY`, `HTTP(S)_PROXY`, `ALL_PROXY`) when set.
- Nostr/geohash remote image URL localization also uses proxy env vars (`BITCHAT_TUI_NOSTR_PROXY`, `HTTP(S)_PROXY`, `ALL_PROXY`) when set.
- `/reply` is a Bluetooth mesh command. `/block` and `/unblock` are Nostr geohash commands for local message filtering by user name.
- Upload now defaults to Blossom on `blossom.nostr.build` (Nostr-signed auth).
- To force provider selection, use `BITCHAT_UPLOAD_PROVIDER`:
  - `blossom` (default)
  - `nostrmedia`
  - `catbox`
  - `0x0`
  - `auto` (try blossom.nostr.build -> nostrmedia -> catbox -> 0x0.st)
- Override full endpoint with `BITCHAT_UPLOAD_ENDPOINT`.
- Optional upload tuning:
  - `BITCHAT_UPLOAD_FIELD` (only used with custom `BITCHAT_UPLOAD_ENDPOINT`)
  - `BITCHAT_UPLOAD_USERHASH` (optional Catbox account hash)
  - `BITCHAT_UPLOAD_TIMEOUT_SECS` (default `45`)
  - `BITCHAT_UPLOAD_MAX_BYTES` (default `536870912`)
