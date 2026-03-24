# Security Audit: sudo-rs Privilege Escalation Analysis

**Target**: sudo-rs (Rust reimplementation of sudo), setuid root at `/usr/bin/sudo`
**Environment**: Default Ubuntu 25.04, default sudoers configuration
**Attacker model**: Local unprivileged user, NOT in sudo group, NOT root
**Date**: 2026-03-24

---

## Executive Summary

After exhaustive source code analysis of all eight attack surfaces, the most
significant finding is a **symlink-following vulnerability in timestamp file
handling** (`secure_open_cookie_file`). The function uses `OpenOptions::open()`
which follows symlinks, instead of `openat()` with `O_NOFOLLOW` — a pattern
the codebase already implements correctly for sudoedit files. Combined with
the policy-free execution of `sudo -K`/`sudo -k`, this creates a code path
where root writes to a file whose path could be redirected via symlink, with
NO authorization check. On this specific system, directory permissions on
`/run` (0755 root:root) prevent creating the necessary symlink, but the
vulnerability exists in the code and would be exploitable on any system where
an attacker gains write access to the timestamp directory hierarchy.

Additionally, the `su` binary unconditionally sets `mark_allow_null_auth_token(true)`,
which combined with `pam_unix.so nullok` in `/etc/pam.d/common-auth`, would
allow passwordless authentication to any account with a truly empty password
field in `/etc/shadow`. No such accounts exist on default Ubuntu 25.04.

---

## CRITICAL FINDING: Symlink-Following in Policy-Free Timestamp Path

### The Vulnerability Chain

**Step 1: Policy-free code path** (`src/sudo/mod.rs:95-108`)

`sudo -K` and `sudo -k` execute **without any sudoers policy check**:

```rust
// mod.rs:95-99 - NO policy check anywhere in this path
SudoAction::RemoveTimestamp(_) => {
    let user = CurrentUser::resolve()?;
    let mut record_file = SessionRecordFile::open_for_user(&user, Duration::default())?;
    record_file.reset()?;  // TRUNCATES and rewrites file as root
    Ok(())
}
```

Compare with `sudo -v` (`pipeline.rs:127-141`) which calls `read_sudoers()` and
`check_validate_permission()`. The `-K`/`-k` paths skip ALL of this.

**Step 2: Symlink-following open** (`src/system/audit.rs:141-151, 195-235`)

`secure_open_cookie_file()` calls `secure_open_impl()` which uses standard
`OpenOptions::open()` — this follows symlinks:

```rust
// audit.rs:230 - FOLLOWS SYMLINKS (no O_NOFOLLOW)
let file = open_options.open(path)?;
let meta = file.metadata()?;     // fstat on fd — checks symlink TARGET
checks(path, meta)?;             // validates TARGET is root-owned
```

The `checks()` function (`audit.rs:167-189`) validates:
- `meta.uid() == 0` (root-owned) ✓
- Not group-writable if gid != 0 ✓
- Not world-writable ✓

But it does **NOT** check:
- Whether the path is a symlink (no `S_ISLNK` check)
- Whether the file is a regular file (no `S_ISREG` check)

Since `file.metadata()` uses `fstat()` on the fd, it returns metadata of the
symlink **target**, not the symlink itself. A symlink pointing to any root-owned,
non-world-writable file passes all checks.

**Step 3: Destructive write to the opened file** (`src/system/timestamp.rs:118-131`)

`reset()` calls `init(0)` which:
```rust
// timestamp.rs:118-131
fn init(&mut self, offset: u64) -> io::Result<()> {
    let lock = FileLock::exclusive(&self.file, false)?;
    self.file.set_len(0)?;          // TRUNCATES file to zero bytes
    self.file.rewind()?;
    self.file.write_all(&Self::MAGIC_NUM.to_le_bytes())?;  // Writes 0xD050
    self.file.write_all(&Self::FILE_VERSION.to_le_bytes())?; // Writes 0x0002
    // ...
}
```

If the fd points to a symlink target (e.g., `/etc/shadow`), this **truncates and
overwrites** the target file with 4 bytes of binary garbage.

**Step 4: The correct pattern exists in the same file** (`src/system/audit.rs:237-259`)

```rust
// audit.rs:237-242 — CORRECT implementation with O_NOFOLLOW
fn open_at(parent: BorrowedFd, file_name: &CStr, create: bool) -> io::Result<OwnedFd> {
    let flags = if create {
        libc::O_NOFOLLOW | libc::O_RDWR | libc::O_CREAT  // O_NOFOLLOW!
    } else {
        libc::O_NOFOLLOW | libc::O_RDONLY                 // O_NOFOLLOW!
    };
    // uses openat() syscall
}
```

This function is used by `traversed_secure_open()` (`audit.rs:291-383`) for
sudoedit. The timestamp code should use this same pattern but doesn't.

### Why It's Not Exploitable on This Specific System

The timestamp file path is `/var/run/sudo-rs/ts/<uid>` (→ `/run/sudo-rs/ts/<uid>`).

To place a symlink, the attacker needs write access to `/run/sudo-rs/ts/`.
This directory is created by `DirBuilder::new().recursive(true).mode(0o711)`
(`audit.rs:206-215`) which creates root-owned directories with mode `rwx--x--x`.

The parent check (`audit.rs:218-221`) only validates the **immediate** parent
directory (`/run/sudo-rs/ts/`), not grandparent directories. But all ancestors
are also root-owned with restrictive permissions:

| Path | Owner | Mode | Attacker can write? |
|------|-------|------|-------------------|
| `/run` | root:root | 0755 | NO |
| `/run/sudo-rs` | root:root | 0711 | NO |
| `/run/sudo-rs/ts` | root:root | 0711 | NO |

**Note**: The effective GID during directory creation is the attacker's GID (the
setuid binary only changes euid, not egid). So directories are created as
`root:<attacker_gid> 0711`. However, mode 0711 gives the group only `--x`
(traverse), no write permission.

### What Would Make It Exploitable

The vulnerability becomes exploitable if **any** of these conditions are met:
1. An attacker gains write access to `/run/sudo-rs/ts/` through another vulnerability
2. The directory is created with incorrect permissions (e.g., if umask interaction
   changed or mode calculation had a bug)
3. The system uses a different tmpfs layout where `/run` or a parent is writable
4. A package or script creates `/run/sudo-rs` with weak permissions before sudo-rs

### Concrete Exploit (if symlink could be placed)

```bash
# Attacker (if they could write to /run/sudo-rs/ts/):
ln -sf /etc/shadow /run/sudo-rs/ts/$(id -u)

# Then run:
sudo -K

# Result: /etc/shadow is truncated to 4 bytes of binary data
# All password authentication on the system breaks
# Attacker can then su to any user (no shadow = no password check)
```

---

## Finding 2: su Binary Allows Null Auth Tokens

### Vulnerability

**File**: `src/su/mod.rs:50`
```rust
pam.mark_allow_null_auth_token(true);  // Allows empty passwords
```

**Comparison with sudo** (`src/sudo/pam.rs:57`):
```rust
pam.mark_allow_null_auth_token(false);  // Correctly disallows empty passwords
```

The `PamContext` constructor defaults to `allow_null_auth_token: true`
(`src/pam/mod.rs:114`). The sudo code explicitly overrides this to `false`, but
the su code explicitly sets it to `true`.

Combined with `/etc/pam.d/common-auth`:
```
auth [success=1 default=ignore] pam_unix.so nullok
```

This means: if a user has a **truly empty** password field in `/etc/shadow`
(not `*`, not `!`, but literally empty `""`), `su` would authenticate them
without prompting for a password.

### Current System Status

All users have locked passwords (`*`, `!`, or `!*`):
```
root:*  daemon:*  ubuntu:!  postgres:!  claude:!  ...
```

No user has an empty password field. The vulnerability is not currently exploitable
but represents a design flaw — `su` should match `sudo`'s behavior of setting
`mark_allow_null_auth_token(false)`.

---

## Finding 3: Pre-Authorization Filesystem Operations as Root

### Vulnerability

`sudo_call()` (`src/system/audit.rs:28-96`) elevates euid to target_user (root
by default) and executes filesystem operations BEFORE `judge()` denies access:

**Execution order** (`src/sudo/pipeline.rs:71-82`):
1. Line 72: `read_sudoers()` — reads config as root
2. Line 76: `Context::from_run_opts()` — calls `sudo_call()` at `context.rs:81`
3. Line 78: `judge()` — policy check (AFTER filesystem ops)

Inside `sudo_call()`, with euid=root:
- `resolve_path()` (`resolve.rs:208-220`) — `stat()` on each PATH entry
- `canonicalize()` (`resolve.rs:308-315`) — `realpath()` resolving symlinks
- `is_valid_executable()` (`resolve.rs:193-202`) — `stat()` + mode check

**Attacker-controlled inputs**:
- `SHELL` env var (when `sudo -s`): read at `resolve.rs:110`, canonicalized with
  euid=root inside `sudo_call`
- `PATH` env var: **overridden by `secure_path`** on default Ubuntu (`sudoers:
  Defaults secure_path=...`). NOT attacker-controllable in default config.

### Assessment

All pre-auth operations are **read-only** (stat, readlink, metadata). No file
writes occur. The attacker can cause:
- Information disclosure (probe filesystem structure via timing/error behavior)
- DoS (point SHELL at a FUSE mount that blocks)
- But NOT arbitrary file write or code execution

### Note on `sudo_call()` comment

`src/system/audit.rs:26-27` states: "This is only used for sudoedit." This is
**incorrect** — `sudo_call()` is also used in `Context::from_run_opts()` (line 81)
and `Context::from_list_opts()` (line 222).

---

## Finding 4: Missing Signal Blocking in `sudo_call()`

**File**: `src/system/audit.rs:86-94`

No signals are blocked during the UID elevation window:
```rust
set_supplementary_groups(&target_groups)?;                    // line 86
cerr(unsafe { libc::setresgid(KEEP_GID, target_gid, KEEP_GID) })?;  // line 88
cerr(unsafe { libc::setresuid(KEEP_UID, target_uid, KEEP_UID) })?;   // line 90
let result = operation();                                     // line 92
std::mem::drop(guard);                                        // line 94
```

Compare with `exec/no_pty.rs:36-46` which correctly calls `SignalSet::full().block()`.

If SIGINT/SIGTERM is delivered between lines 86-94, the default handler terminates
the process with euid still elevated. The `ResetUserGuard::drop()` (`audit.rs:70-81`)
uses `.expect()` which panics on setresuid failure — running the panic handler with
elevated euid before aborting.

**Impact**: DoS only. Process death does not enable privilege escalation.

---

## Finding 5: Sudoers Parser Follows Symlinks

**File**: `src/system/audit.rs:133-138`

`secure_open_sudoers()` uses `OpenOptions::open()` (follows symlinks), same issue
as the timestamp file. The `@includedir /etc/sudoers.d` processing
(`src/sudoers/mod.rs`) does not filter symlinks during directory enumeration.

**Not exploitable**: `/etc/sudoers.d` is root-owned 0755. Attacker cannot create
symlinks there.

---

## Finding 6: System Configuration Notes

| Setting | Value | Expected | Impact |
|---------|-------|----------|--------|
| `fs.protected_symlinks` | 0 | 1 | Reduced kernel-level symlink protection |
| `fs.protected_hardlinks` | 0 | 1 | Allows hardlinks to unowned files |
| `/run` permissions | 0755 root:root | 0755 root:root | Correct |
| NSS config | files only | files only | No network-based lookup attacks |

The disabled kernel symlink/hardlink protections are unusual but do not directly
enable exploitation because the relevant directories are not world-writable.

---

## Summary Table

| # | Finding | Severity | Exploitable? | Blocked By |
|---|---------|----------|-------------|------------|
| 1 | Missing O_NOFOLLOW in timestamp open | **HIGH** | Mitigated | Directory perms (0711 root) |
| 2 | su allows null auth tokens | MEDIUM | No | No empty-password users |
| 3 | Pre-auth fs ops as root | LOW | No | Read-only operations |
| 4 | No signal blocking in sudo_call | LOW | No | Process death ≠ escalation |
| 5 | Sudoers parser follows symlinks | LOW | No | Directory perms |
| 6 | AppArmor dlopen | NONE | No | Runs after authorization |
| 7 | Argument parsing side effects | NONE | No | No side effects |
| 8 | NSS race condition | NONE | No | Files-only config |

---

## Recommendations

### P0: Use `O_NOFOLLOW` in `secure_open_cookie_file()` and `secure_open_sudoers()`

**Files**: `src/system/audit.rs:141-151`, `src/system/audit.rs:133-138`

Replace `OpenOptions::open()` with the `openat(O_NOFOLLOW)` pattern already
implemented at `audit.rs:237-259`. This eliminates the entire class of
symlink-following bugs rather than relying on directory permissions as the
sole defense.

### P1: Set `mark_allow_null_auth_token(false)` in `su`

**File**: `src/su/mod.rs:50`

Change to match sudo's behavior. There is no legitimate reason for `su` to
accept null authentication tokens.

### P2: Block signals during `sudo_call()` UID elevation

**File**: `src/system/audit.rs:28-96`

Add `SignalSet::full().block()` before setresuid/setresgid, matching
`exec/no_pty.rs:36-46`.

### P3: Replace `.expect()` with `libc::abort()` in `ResetUserGuard::drop()`

**File**: `src/system/audit.rs:70-81`

Avoid running the Rust panic handler at elevated euid.

### P4: Filter symlinks in `@includedir` processing

**File**: `src/sudoers/mod.rs` (includedir handling)

Add `is_symlink()` check during directory enumeration.

### P5: Fix misleading comment on `sudo_call()`

**File**: `src/system/audit.rs:26-27`

Update "only used for sudoedit" to reflect actual usage in `from_run_opts()`
and `from_list_opts()`.
