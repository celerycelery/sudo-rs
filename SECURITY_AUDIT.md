# Security Audit: sudo-rs

**Date:** 2026-03-24
**Scope:** Privilege escalation from unprivileged local user (not in sudo group, not root) on default Ubuntu 25.04
**Binary:** setuid root `/usr/bin/sudo` (sudo-rs), also `/usr/bin/su` (sudo-rs)

---

## CONFIRMED VULNERABILITY

### V1: PAM Null Auth Token Bypass in `su` Binary (HIGH)

**Commit:** bff77da ("fix failing compliance test", 2026-03-20)
**File:** `src/su/mod.rs:50`
**Severity:** HIGH (authentication bypass, potentially chained to root)

#### Description

Commit bff77da changed `pam.mark_allow_null_auth_token(false)` to
`pam.mark_allow_null_auth_token(true)` in the `su` binary's
`authenticate()` function. This removes the `PAM_DISALLOW_NULL_AUTHTOK`
flag from `pam_authenticate()` and `pam_acct_mgmt()` calls.

On default Ubuntu 25.04, `/etc/pam.d/common-auth` configures:
```
auth [success=1 default=ignore] pam_unix.so nullok
```

With `nullok` enabled AND `PAM_DISALLOW_NULL_AUTHTOK` not set, PAM will
authenticate any user with an empty password field in `/etc/shadow`
**without requiring any credentials**.

#### Code Path

```
su [target_user]
  → authenticate() (src/su/mod.rs:23)
    → pam.mark_allow_null_auth_token(true)    ← VULNERABLE (line 50)
    → pam.authenticate(user)                  ← PAM_DISALLOW_NULL_AUTHTOK not set
      → pam_authenticate(pamh, 0)             ← flags=0, no null-auth protection
        → pam_unix.so (nullok)                ← accepts empty password
```

#### Comparison with sudo

The `sudo` binary correctly sets this to `false`:
```rust
// src/sudo/pam.rs:57
pam.mark_allow_null_auth_token(false);  // CORRECT
```

#### Exploitation

```bash
# As unprivileged user, su to any account with empty password field
su targetuser -c 'id'
# No password prompt — authentication succeeds silently
```

**Prerequisite:** A target account must have an empty (not `!`/`*` locked,
but truly empty `""`) password field in `/etc/shadow`. Default Ubuntu
system accounts use `!` or `*` (locked), which is distinct from empty.
However:

1. Accounts created with `passwd -d username` have empty passwords
2. Some third-party packages or admin scripts create accounts with empty
   passwords
3. The `nullok` option in pam_unix is specifically designed to handle this
   case, and `PAM_DISALLOW_NULL_AUTHTOK` is the safety net — removing it
   defeats the defense-in-depth

#### Root Cause

The commit was made to fix a compliance test
(`passwordless_accounts_dont_require_auth`) that expected `su` to succeed
for passwordless accounts. The fix should have been to validate the test's
assumptions, not to weaken authentication security. The test itself
(`test-framework/sudo-compliance-tests/src/su/pam.rs:22-35`) creates an
account with `passwd -d`, then expects `su` to succeed without credentials.

#### Fix

```diff
-    pam.mark_allow_null_auth_token(true);
+    pam.mark_allow_null_auth_token(false);
```

---

## INVESTIGATED AREAS — NO EXPLOITABLE VULNERABILITY FOUND

### A1: Pre-Authorization Privilege Window

**Files:** `src/common/context.rs:81-83`, `src/system/audit.rs:28-96`

#### Finding

`sudo_call()` temporarily sets euid to the target user (root by default)
and runs `CommandAndArguments::build_from_args()` BEFORE the policy check
(`judge()` at `src/sudo/pipeline.rs:78`). Inside this privileged closure:

- `resolve_path()` calls `is_valid_executable()` → `path.is_file()` +
  `fs::metadata()` (read-only stat operations)
- `canonicalize()` calls `fs::canonicalize()` (readlink) + `fs::metadata()`
  (read-only stat)

**Why not exploitable:**
- All operations are **read-only** (stat, readlink) — no file creation,
  no writes, no side effects
- Default Ubuntu sudoers sets `secure_path`, so the attacker's `PATH` is
  not used for command resolution
- `SHELL` is only used when `-s` flag is passed; it's read via
  `env::var("SHELL")` and then stat'd — still read-only
- FUSE/named-pipe hangs would be DoS only, not privilege escalation
- No TOCTOU concern because the command is resolved again or the denial
  prevents execution entirely

#### Code References
- `src/common/context.rs:76-84` — `Context::from_run_opts()` calls
  `sudo_call()` before `judge()` is called at `pipeline.rs:78`
- `src/common/command.rs:66-109` — `build_from_args()` operations
- `src/common/resolve.rs:193-220` — `is_valid_executable()`, `resolve_path()`

### A2: Timestamp File Operations (sudo -K / sudo -k)

**Files:** `src/sudo/mod.rs:95-109`, `src/system/audit.rs:141-234`,
`src/system/timestamp.rs`

#### Finding

`sudo -K` (RemoveTimestamp) and `sudo -k` (ResetTimestamp) execute WITHOUT
a sudoers policy check and run as root. They open/create timestamp files
at `/var/run/sudo-rs/ts/{uid}`.

`secure_open_impl()` (audit.rs:195-234) does NOT use `O_NOFOLLOW` on the
timestamp file open (line 230), and uses `std::fs::metadata()` (which
follows symlinks) for the parent directory check (line 219). This contrasts
with the sudoedit path which correctly uses `O_NOFOLLOW` (line 238-241).

**Why not exploitable:**
- `/var/run/` is owned by root with mode `0755` — an unprivileged user
  **cannot create** `/var/run/sudo-rs/` or any symlinks within it
- When sudo creates `/var/run/sudo-rs/ts/`, it uses mode `0711`
  (owner rwx, others x-only) — unprivileged users cannot write to it
- The `checks()` function (audit.rs:167-188) verifies root ownership and
  rejects world-writable or group-writable (non-root) paths
- Even with a symlink in place, the target would need to pass ownership
  checks (must be owned by uid 0)

**Defense-in-depth weakness:** The absence of `O_NOFOLLOW` on timestamp
file opens is an unnecessary risk. If directory permissions were ever
weakened (e.g., by a packaging bug), this could become exploitable. The
sudoedit path already demonstrates the correct pattern with `O_NOFOLLOW`.

### A3: Sudoers Parser Include Processing

**Files:** `src/sudoers/mod.rs:701-837`, `src/system/audit.rs:132-138`

#### Finding

Include files are opened via `open_subsudoers()` → `secure_open_sudoers(path, true)`
→ `secure_open_impl()` with `check_parent_dir=true, create_parent_dirs=false`.

The `checks()` function verifies:
1. File must be owned by uid 0
2. File must not be group-writable (unless group is root)
3. File must not be world-writable
4. Parent directory passes the same checks

For `@includedir`, entries are filtered (line 820): files containing `.`
or ending with `~` are skipped. Entries are sorted before processing.

**Why not exploitable:**
- `/etc/sudoers.d/` is owned by root with restricted permissions
- All included files must pass root-ownership checks
- `secure_open_sudoers` verifies parent directory security
- An unprivileged user cannot create files in `/etc/sudoers.d/`
- Symlinks in the include path would resolve to targets that fail ownership checks

**Note:** `secure_open_sudoers` also does not use `O_NOFOLLOW` (it uses
`OpenOptions::open()`), but the ownership checks prevent exploitation.

### A4: AppArmor dlopen

**File:** `src/apparmor.rs:30`

#### Finding

`dlopen("libapparmor.so.1")` is called at `pipeline.rs:109`, which is
AFTER authorization (line 80) and AFTER PAM authentication (line 84).

**Why not exploitable:**
- Code only runs post-authorization — denied users never reach it
- `LD_LIBRARY_PATH` is ignored for setuid binaries by the dynamic linker
- Feature-gated behind `#[cfg(feature = "apparmor")]`
- No RPATH/RUNPATH concerns in the build configuration

### A5: File Descriptor Leaks and Signal Races

**Files:** `src/system/audit.rs:68-96`, `src/system/mod.rs:48-112`

#### Finding

- `ResetUserGuard::drop()` (audit.rs:70-81) calls `.expect()` if
  `setresuid` fails — this would panic
- File descriptors are properly marked `CLOEXEC` throughout
- No signal handlers are installed during the pre-auth phase

**Why not exploitable:**
- `setresuid` restoring saved UIDs should never fail in practice
- A panic would abort the process, not leave it running with elevated privs
- Pre-auth signal delivery uses default handlers (process termination),
  which is safe
- The setuid bit causes the kernel to clear `PR_SET_DUMPABLE`, preventing
  core dumps from leaking privileged memory

**Code quality issue:** The `.expect()` in `ResetUserGuard::drop()` should
be replaced with `process::abort()` to avoid unwinding through potentially
unsafe code during privilege restoration failure.

### A6: Argument Parsing Side Effects

**File:** `src/sudo/cli/mod.rs`

#### Finding

`SudoAction::from_env()` is purely syntactic parsing. The only side effect
is `-E/--preserve-env=VAR1,VAR2` which reads environment variables into
memory (no file I/O, no execution).

- `-e` (sudoedit): No temporary files created during parsing
- `-A` (askpass): `SUDO_ASKPASS` program is only executed post-authorization
  in a child process that first drops privileges
- Editor selection (sudoedit): Only happens post-authorization

**Not exploitable.** No side effects during argument parsing.

### A7: NSS Module Loading During User Resolution

**Files:** `src/common/resolve.rs:119-175`, `src/system/mod.rs:420-504`

#### Finding

User resolution via `getpwnam_r()`/`getpwuid_r()`/`getgrouplist()` triggers
NSS modules. On default Ubuntu:
```
passwd: files systemd
group:  files systemd
```

**Why not exploitable:**
- Default Ubuntu uses only `files` and `systemd` NSS backends
- Neither can be influenced by an unprivileged user
- `/etc/nsswitch.conf` is root-owned
- NSS modules are loaded from system library paths only (setuid binary)

### A8: Race Condition in Context Building

**File:** `src/common/context.rs:49-84`

#### Finding

Target user resolution happens before the policy check. Between user
resolution and policy evaluation, an attacker could theoretically modify
user databases. However:
- `/etc/passwd` and `/etc/shadow` are root-owned
- NSS backends are not user-controllable on default Ubuntu
- Even if the user changed between resolution and policy check, the policy
  check uses the already-resolved `User` struct

**Not exploitable.**

---

## SUMMARY

| ID | Area | Severity | Exploitable? | Finding |
|----|------|----------|--------------|---------|
| V1 | su PAM null auth | HIGH | YES (conditional) | `mark_allow_null_auth_token(true)` bypasses password requirement for empty-password accounts |
| A1 | Pre-auth privilege window | LOW | No | Read-only fs operations; secure_path prevents attacker PATH |
| A2 | Timestamp symlink | LOW | No | /var/run owned by root; directory not writable by attacker |
| A3 | Sudoers parser includes | LOW | No | Root ownership checks prevent attacker-controlled files |
| A4 | AppArmor dlopen | NONE | No | Post-authorization only; LD_LIBRARY_PATH ignored |
| A5 | FD leaks / signals | LOW | No | Proper CLOEXEC; panic on setresuid failure is code quality issue |
| A6 | Argument parsing | NONE | No | Pure syntactic parsing; no side effects |
| A7 | NSS modules | NONE | No | Default Ubuntu uses files/systemd only |
| A8 | Context building race | NONE | No | User databases not attacker-controllable |

### Defense-in-Depth Recommendations

1. **Fix V1 immediately:** Revert `mark_allow_null_auth_token` to `false` in `src/su/mod.rs:50`
2. **Add O_NOFOLLOW to timestamp opens:** `secure_open_cookie_file()` should use `O_NOFOLLOW` like `open_at()` does for sudoedit
3. **Replace panic in ResetUserGuard:** Use `process::abort()` instead of `.expect()` in the Drop impl
4. **Explicitly disable core dumps:** Call `prctl(PR_SET_DUMPABLE, 0)` early in initialization (defense-in-depth, though kernel handles this for setuid)
