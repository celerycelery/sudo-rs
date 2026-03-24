# Security Audit: sudo-rs Privilege Escalation Analysis

**Target**: sudo-rs (Rust reimplementation of sudo), setuid root at `/usr/bin/sudo`
**Environment**: Default Ubuntu 25.04, default sudoers configuration
**Attacker model**: Local unprivileged user, NOT in sudo group, NOT root
**Date**: 2026-03-24

---

## Executive Summary

After thorough source code analysis of all eight attack surfaces, **no concrete exploit
was found** that allows an unprivileged user to achieve arbitrary code execution as
root, arbitrary file write as root, or authentication bypass on a default Ubuntu 25.04
system with unmodified sudoers configuration.

However, several **defense-in-depth weaknesses** were identified that could become
exploitable under non-default configurations or in combination with other vulnerabilities.
These are documented below with severity ratings.

---

## 1. PRE-AUTHORIZATION PRIVILEGE WINDOW

### Finding: `sudo_call()` executes filesystem operations as target_user BEFORE policy check

**Severity**: LOW (info leak / DoS only on default config)
**Exploitable on default Ubuntu**: NO

**Code path** (confirmed by source reading):
1. `pipeline.rs:72` — `read_sudoers()` (parses sudoers, still euid=root)
2. `pipeline.rs:76` — `Context::from_run_opts()` calls `sudo_call()` at `context.rs:81`
3. `pipeline.rs:78` — `judge()` — policy check happens HERE (after filesystem ops)

Inside `sudo_call()` (`audit.rs:28-96`), the process calls `setresuid()` to the
target user's euid (root by default, line 90), then executes the closure:
- `CommandAndArguments::build_from_args()` (`command.rs:66-109`)
  - `resolve_path()` — iterates PATH entries, calls `is_valid_executable()` → `fs::metadata()` per entry
  - `canonicalize()` → `fs::canonicalize(parent)` — resolves symlinks with elevated euid

**What the attacker controls**:
- **SHELL env var** (`resolve.rs:110`): When `sudo -s` is used, `env::var("SHELL")` is read
  and the value is passed to `build_from_args()` as the shell. `canonicalize()` then resolves
  this attacker-controlled path with euid=root.
- **PATH env var**: On default Ubuntu, `Defaults secure_path=...` is set in sudoers, so
  `policy.search_path()` (`policy.rs:159-167`) returns the secure_path, **overriding** the
  user's PATH. The attacker's PATH is NOT used.
- **Command arguments**: Positional args control what path is resolved.

**Why not exploitable on default Ubuntu**:
- All filesystem operations are read-only (stat, readlink, metadata). No files are written.
- SHELL-based attack requires `sudo -s` which still goes through policy check and is denied.
- PATH is overridden by secure_path from sudoers.
- The attacker gets a "not allowed to run" error after these operations, but cannot
  leverage the brief privilege window for writes.

**Potential exploitation under non-default configs**:
- If `secure_path` is removed from sudoers, the attacker's PATH could cause root to
  stat arbitrary paths (info disclosure via timing, FUSE-based attacks, DoS via
  hanging named pipes).

**Note**: The comment at `audit.rs:26-27` says `sudo_call()` is "only used for sudoedit"
but it is also used in `from_run_opts()` (line 81) and `from_list_opts()` (line 222).
This is a misleading comment.

---

## 2. POLICY-FREE TIMESTAMP CODE PATHS (sudo -K / sudo -k)

### Finding: `-K` and `-k` execute without policy check but directory permissions prevent exploitation

**Severity**: LOW (not exploitable due to directory permissions)
**Exploitable on default Ubuntu**: NO

**Code path** (`mod.rs:95-108`):
```rust
SudoAction::RemoveTimestamp(_) => {
    let user = CurrentUser::resolve()?;
    let mut record_file = SessionRecordFile::open_for_user(&user, Duration::default())?;
    record_file.reset()?;  // truncates and rewrites the file
    Ok(())
}
```

This calls `secure_open_cookie_file()` (`audit.rs:141-151`) → `secure_open_impl()` with
`create_parent_dirs=true`. The timestamp file path is `/var/run/sudo-rs/ts/<uid>`.

**The symlink attack theory**:
- `secure_open_impl()` at line 230 uses `open_options.open(path)` — standard Rust
  `OpenOptions` which follows symlinks (no `O_NOFOLLOW`).
- If the attacker could place a symlink at `/var/run/sudo-rs/ts/<uid>` → `/etc/shadow`,
  then `reset()` would truncate and overwrite the target file.
- The `checks()` function (line 167-189) validates the opened file is root-owned and
  not world-writable — but it checks the symlink **target's** metadata, which `/etc/shadow`
  would pass.

**Why not exploitable on default Ubuntu**:
- `/var/run` (symlink to `/run`) is root:root mode 0755 — unprivileged users cannot
  create files or directories.
- If `/var/run/sudo-rs/ts/` is created by sudo, it's root-owned mode 0711 — unprivileged
  users cannot create symlinks inside.
- The attacker can only target their own UID's timestamp file (the code uses
  `user.uid` from `CurrentUser::resolve()`), and they cannot write to the directory.

**Defense-in-depth weakness**:
The code SHOULD use `O_NOFOLLOW` (via `openat()` like `open_at()` at line 237-259 does)
rather than relying solely on directory permissions. The correct pattern already exists
in the codebase at `traversed_secure_open()` (line 291-383) which uses `O_NOFOLLOW`.

**Comparison with correct implementation in same codebase**:
```
secure_open_cookie_file → OpenOptions::open()     — follows symlinks (WEAK)
open_at()               → openat(O_NOFOLLOW)      — rejects symlinks (STRONG)
```

---

## 3. su BINARY NULL AUTH TOKEN

### Finding: `mark_allow_null_auth_token(true)` has no effect on default Ubuntu

**Severity**: LOW (no users with empty passwords on default Ubuntu)
**Exploitable on default Ubuntu**: NO

**Code path** (`su/mod.rs:50`):
```rust
pam.mark_allow_null_auth_token(true);
```

This causes `pam_authenticate()` to be called WITHOUT the `PAM_DISALLOW_NULL_AUTHTOK`
flag (`pam/mod.rs:144-150`), combined with `pam_unix.so nullok` in
`/etc/pam.d/common-auth`.

**Why not exploitable on default Ubuntu**:
All system users in `/etc/shadow` have locked passwords (`*` or `!` or `!*`):
```
root *     daemon *     bin *      sys *      sync *
games *    nobody *     ubuntu !   claude !   ...
```

- `*` = locked account, pam_unix rejects authentication
- `!` = locked account, pam_unix rejects authentication
- Neither is an "empty" password field

`nullok` allows authentication for users with a truly **empty** password field (empty
string between the first and second `:` in `/etc/shadow`). No such users exist on
default Ubuntu 25.04.

**Note**: `sudo` correctly sets `mark_allow_null_auth_token(false)` at `sudo/pam.rs`,
while `su` sets it to `true`. This inconsistency is a design concern but not
exploitable without a user that has a genuinely empty password.

---

## 4. SUDOERS PARSER SYMLINK HANDLING

### Finding: `secure_open_sudoers()` follows symlinks but directory permissions prevent exploitation

**Severity**: LOW (not exploitable — /etc/sudoers.d is root-owned)
**Exploitable on default Ubuntu**: NO

**Code path** (`audit.rs:133-138`):
```rust
pub fn secure_open_sudoers(path: impl AsRef<Path>, check_parent_dir: bool) -> io::Result<File> {
    let mut open_options = OpenOptions::new();
    open_options.read(true);  // No O_NOFOLLOW
    secure_open_impl(path.as_ref(), &mut open_options, check_parent_dir, false)
}
```

`@includedir /etc/sudoers.d` processing (`sudoers/mod.rs:794-838`) enumerates
directory entries and passes each to `secure_open_sudoers()`. Symlinks are not
filtered out during enumeration (no `is_symlink()` check).

**Why not exploitable on default Ubuntu**:
- `/etc/sudoers.d/` is root-owned with restricted permissions. An unprivileged user
  cannot create symlinks or files there.
- `checks()` validates opened files are root-owned and not world/group-writable.
- The include limit (`INCLUDE_LIMIT = 128`) prevents infinite loops.

**Defense-in-depth weakness**:
Same as finding #2 — should use `O_NOFOLLOW` via `openat()`.

---

## 5. FILE DESCRIPTOR AND SIGNAL RACES

### Finding: No signal blocking during `sudo_call()` UID elevation; panic in Drop handler

**Severity**: LOW (DoS only, not privilege escalation)
**Exploitable on default Ubuntu**: NO (no privilege escalation possible)

**Issue 1: No signal blocking** (`audit.rs:86-92`):
```rust
set_supplementary_groups(&target_groups)?;        // line 86
cerr(unsafe { libc::setresgid(...) })?;           // line 88
cerr(unsafe { libc::setresuid(...) })?;           // line 90
let result = operation();                          // line 92
```

Between lines 86-92, if SIGINT/SIGTERM is delivered, the default kernel handler
terminates the process with euid still elevated. However, the process is dead — there
is no way to continue execution or exploit the elevated euid of a terminated process.

Compare with `exec/no_pty.rs:36-46` which correctly blocks signals with
`SignalSet::full().block()` before sensitive operations.

**Issue 2: `.expect()` in `ResetUserGuard::drop()`** (`audit.rs:70-81`):
```rust
impl Drop for ResetUserGuard {
    fn drop(&mut self) {
        (|| { /* setresuid, setresgid, set_supplementary_groups */ })()
            .expect("could not restore to saved user id");  // PANICS if setresuid fails
    }
}
```

If `setresuid()` fails in drop (e.g., due to LSM blocking), `.expect()` panics.
If this occurs during unwinding (double panic), the process aborts via `libc::abort()`.
The process terminates with euid elevated, but is immediately dead.

**Why not exploitable**: A killed/aborted process cannot be leveraged for privilege
escalation. The only impact is denial of service (crash).

**Issue 3: FD leaks in error paths**:
Operations inside `sudo_call()` closures are read-only (stat, readlink). No file
descriptors are opened for writing. Even if an error occurs and the closure returns
early, no writable FDs leak to unprivileged code.

---

## 6. DLOPEN IN APPARMOR MODULE

### Finding: dlopen occurs AFTER authorization; not exploitable

**Severity**: NONE
**Exploitable on default Ubuntu**: NO

**Code path** (`pipeline.rs:107-111`):
```rust
#[cfg(feature = "apparmor")]
if let Some(profile) = &controls.apparmor_profile {
    crate::apparmor::set_profile_for_next_exec(profile)  // line 109
```

This is called AFTER `judge()` (line 78) and AFTER `auth_and_update_record_file()` (line 84).
An unauthorized user never reaches this code.

The `dlopen("libapparmor.so.1")` call at `apparmor.rs:30`:
- Uses hardcoded library name (not user-controllable)
- Setuid status causes the dynamic linker to ignore `LD_LIBRARY_PATH`
- The installed binary's RUNPATH is `/usr/libexec/sudo` (root-owned, not attacker-writable)

---

## 7. ARGUMENT PARSING SIDE EFFECTS

### Finding: No exploitable side effects during argument parsing

**Severity**: NONE
**Exploitable on default Ubuntu**: NO

`SudoAction::from_env()` (`mod.rs:85`) parses CLI arguments before any policy check.
Analysis:
- **`-e` (sudoedit)**: Only sets flags. Temporary files are created AFTER fork and
  AFTER authentication in `handle_child_inner()` (`edit.rs:213+`). Privileges are
  explicitly dropped via `irrevocably_drop_privileges()`.
- **`-A` (askpass)**: `SUDO_ASKPASS` env var is read but the program is NOT executed
  until authentication phase. The program must be an absolute path (`rpassword.rs:408`).
  The askpass child drops privileges via `irrevocably_drop_privileges()` (`askpass.rs:48`).
- **Malformed arguments**: Parsing returns `Result<Self, String>` without I/O side effects.
  Environment variable syntax is validated (`cli/mod.rs:596-607`): only alphanumeric +
  underscore allowed in names.

---

## 8. NSS RACE CONDITION

### Finding: Files-only NSS configuration eliminates this vector

**Severity**: NONE
**Exploitable on default Ubuntu**: NO

`/etc/nsswitch.conf`:
```
passwd:         files
group:          files
shadow:         files
```

User/group resolution uses `getpwnam_r()` (`system/mod.rs:479-504`) — the reentrant,
thread-safe variant. With files-only NSS, lookups are atomic reads from
`/etc/passwd` and `/etc/group` (root-owned, not attacker-writable).

No LDAP, NIS, or custom NSS modules are loaded that could be influenced by an
unprivileged user.

---

## Summary Table

| # | Attack Surface | Exploitable? | Severity | Root Cause |
|---|---------------|-------------|----------|------------|
| 1 | Pre-auth privilege window | NO | LOW | Read-only fs ops; secure_path overrides PATH |
| 2 | Timestamp symlink (sudo -K/-k) | NO | LOW | Dir perms prevent symlink creation |
| 3 | su null auth token | NO | LOW | No empty-password users on default Ubuntu |
| 4 | Sudoers parser symlinks | NO | LOW | /etc/sudoers.d is root-owned |
| 5 | Signal/FD races in sudo_call | NO | LOW | Process death ≠ privilege escalation |
| 6 | AppArmor dlopen | NO | NONE | Runs after authorization |
| 7 | Argument parsing | NO | NONE | No side effects during parsing |
| 8 | NSS race condition | NO | NONE | Files-only NSS config |

---

## Defense-in-Depth Recommendations

While none of these issues are exploitable on default Ubuntu 25.04, the following
code improvements would harden sudo-rs against non-default configurations and
future regressions:

### P1: Use `O_NOFOLLOW` in `secure_open_cookie_file()` and `secure_open_sudoers()`
**Files**: `src/system/audit.rs:141-151`, `src/system/audit.rs:133-138`

Both functions use `OpenOptions::open()` which follows symlinks. The correct pattern
(`openat()` with `O_NOFOLLOW`) already exists at `audit.rs:237-259`. Applying it to
cookie files and sudoers would eliminate symlink-following as a class of bug, rather
than relying on directory permissions as the sole defense.

### P2: Block signals during `sudo_call()` UID elevation
**File**: `src/system/audit.rs:28-96`

Add `SignalSet::full().block()` before `setresuid()` and restore after `drop(guard)`,
matching the pattern used in `exec/no_pty.rs:36-46`.

### P3: Replace `.expect()` with `libc::abort()` in `ResetUserGuard::drop()`
**File**: `src/system/audit.rs:70-81`

Using `unsafe { libc::abort() }` instead of `.expect()` avoids running the Rust panic
handler (which prints backtraces and runs destructors) while euid may still be elevated.

### P4: Update misleading comment on `sudo_call()`
**File**: `src/system/audit.rs:26-27`

The comment says "This is only used for sudoedit" but `sudo_call()` is also used in
`Context::from_run_opts()` and `Context::from_list_opts()`.

### P5: Filter symlinks in `@includedir` processing
**File**: `src/sudoers/mod.rs:816-825`

Add `!direntry.file_type().ok()?.is_symlink()` to the `filter_map` to explicitly
reject symlinks during directory enumeration, rather than relying solely on
`secure_open_sudoers()` checks.

---

## Methodology

Each attack surface was analyzed by:
1. Reading the actual source code and tracing exact execution paths
2. Verifying system configuration (`/etc/sudoers`, `/etc/pam.d/`, `/etc/shadow`,
   `/etc/nsswitch.conf`, filesystem permissions on `/var/run`)
3. Identifying what an unprivileged attacker controls (env vars, arguments, filesystem objects)
4. Determining whether controlled inputs can cause side effects during the privilege window
5. Proving or disproving exploitability against the actual default configuration
