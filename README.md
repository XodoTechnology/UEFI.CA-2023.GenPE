# GenPE — UEFI CA 2023 Secure Boot updater for Windows / WinPE

A single, dependency-free `GenPE.exe` (~1.6 MB, imports only `kernel32.dll`,
`advapi32.dll`, `msvcrt.dll`) that enrolls the **Microsoft 2023 Secure Boot
certificates** into UEFI firmware and marks Windows installs — online or
offline — as updated. Built to run from a **custom Windows PE disk** so you can
service machines that haven't received the update through Windows Update,
machines that were imaged/upgraded offline, and everything in between.

## Why

The 2011 "Microsoft Corporation UEFI CA" and friends expire in 2026. Microsoft's
normal rollout path is Windows Update servicing (`AvailableUpdates = 0x5944`),
which doesn't help machines that are offline, on custom WinPE media, or on OSes
that were upgraded outside the servicing flow. This tool performs the same
firmware writes directly, using Microsoft's own **signed** update payloads from
[github.com/microsoft/secureboot_objects](https://github.com/microsoft/secureboot_objects),
all embedded in the exe — nothing to download, nothing to install.

| Certificate | Variable | Notes |
|---|---|---|
| Microsoft Corporation KEK 2K CA 2023 | `KEK` | signed by each OEM's PK — the tool picks the right one for your device automatically |
| Windows UEFI CA 2023 | `db` | required for the 2023-signed Windows boot manager |
| Microsoft UEFI CA 2023 | `db` | 3rd-party / option-ROM / shim signing |
| Microsoft Option ROM UEFI CA 2023 | `db` | optional (`--orom`) |
| dbx revocation updates | `dbx` | optional and guarded (`--dbx`, `--dbx-svn`, `--dbx-2024`) |

All writes are **authenticated append writes** (`EFI_VARIABLE_APPEND_WRITE`).
The tool never performs a replace write on Secure Boot databases with its
embedded payloads, so existing db/KEK contents (OEM certs, custom keys) are
preserved.

## Usage

```
genpe status                      Show Secure Boot certs + OS servicing state
genpe scan                        List Windows installs on attached disks
genpe install --yes               Enroll KEK 2023 + db 2023 CAs, mark OS updated
    --orom                          also enroll Option ROM UEFI CA 2023
    --kek-only | --db-only          restrict which variables are updated
    --dbx [--dbx-svn] [--dbx-2024]  also apply dbx revocation updates
    --no-mark                       do not write OS registry state
genpe mark [X:] [--pending]       Mark an OS Updated (or Pending) — running
                                  OS if no drive, offline OS at X:\ otherwise
genpe optin [X:] [--mask 0x5944]  Set AvailableUpdates so OS servicing applies
                                  the certs on next boot
genpe dump [name [out.bin]]       List / extract an embedded signed payload
genpe apply <PK|KEK|db|dbx> file  Apply an external signed payload (--yes;
                                  --replace to overwrite instead of append)
```

### Typical WinPE flow

```bat
X:\> GenPE.exe status          :: see what's enrolled / missing
X:\> GenPE.exe install --yes   :: KEK 2023 + Windows UEFI CA 2023 + MS UEFI CA 2023
X:\> GenPE.exe scan            :: find offline Windows installs on the disks
X:\> GenPE.exe mark C:         :: tell that OS it's updated (writes its registry)
```

Or, to leave the firmware alone and let an offline OS update itself at next
boot via Microsoft's servicing stack:

```bat
X:\> GenPE.exe optin D:        :: writes AvailableUpdates=0x5944 into D:'s SYSTEM hive
```

### How `install` works

1. Reads `PK`, SHA-1-fingerprints the enrolled Platform Key cert, and looks it
   up in Microsoft's `kek_update_map.json` (488 PKs, 60 vendors embedded) to
   select the KEK update **signed by that device's own PK vendor**.
2. Appends the KEK 2K CA 2023 update to `KEK` (skips if already present).
3. Appends `Windows UEFI CA 2023` then `Microsoft UEFI CA 2023` to `db`
   (skips whatever is already enrolled; `--orom` adds the Option ROM CA).
4. Verifies each cert is visible after the write.
5. Sets `HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot` →
   `UEFICA2023Status="Updated"`, `UEFICA2023Error=0`, `AvailableUpdates=0`
   unless `--no-mark`.

### Offline OS marking

`genpe mark X:` mounts `X:\Windows\System32\config\SYSTEM` under a temporary
key, resolves `Select\Current` to the right `ControlSetNNN`, and writes the
same servicing values — so an OS that was patched/imaged while offline reports
correctly (and doesn't re-run the rollout) on next boot. `mark X: --pending`
or `optin X:` does the opposite: sets `AvailableUpdates` so Microsoft's own
servicing performs the rollout at first boot.

## Safety notes

- **Back up BitLocker recovery keys** before changing Secure Boot state.
- `--dbx-svn` / `--dbx-2024` revoke pre-2023 Windows boot managers. Only use
  them after a Windows UEFI CA 2023-signed boot manager is on the ESP — the
  tool warns and requires the db update first, but **you** are responsible for
  the boot files. The standard `optin` path lets Microsoft handle ordering.
- Devices with a PK not in Microsoft's vendor map can't get a signed KEK
  update this way; `status` tells you, and `apply` accepts an OEM-provided
  signed payload.
- Requires UEFI boot + admin/SYSTEM (standard in WinPE). On legacy/CSM boots
  it exits cleanly with an error.

## Building

Linux cross-compile (only needs `gcc-mingw-w64` + `python3`):

```sh
make            # build/GenPE.exe    (x64)
make x86        # build/GenPE32.exe  (x86, if i686-w64-mingw32-gcc present)
make test       # run the parser/map unit tests natively against real payloads
```

On Windows with mingw-w64 installed, the same Makefile works under MSYS2.
`tools/embed.py` regenerates `src/generated/payloads.{S,h}` from `payloads/`
— re-run it after refreshing the payload set (`make` does this automatically).

## Layout

```
src/genpe.c        the tool (UEFI var I/O, registry, CLI)
src/sigparse.h     EFI_SIGNATURE_LIST parsing + PK->KEK map lookup
src/sha1.h         tiny SHA-1 (cert thumbprints)
src/generated/     payloads.S / payloads.h (generated, do not edit)
tools/embed.py     embeds payloads/*.bin into the binary
payloads/          Microsoft-signed update .bin files + kek_map.json
tests/             native unit test for parsing/map logic
```

## Payload provenance

Everything in `payloads/` is byte-for-byte from
`microsoft/secureboot_objects` `PostSignedObjects/` (plus
`kek_update_map.json`). They are already signed by Microsoft/OEM keys — this
tool just transports and applies them; it cannot and does not sign anything.

## License

MIT (tool code). Payload `.bin` files are Microsoft's signed update objects —
see the source repository for their terms.
