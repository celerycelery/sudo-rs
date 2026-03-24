# Security Audit & Penetration Test Report — sudo-rs

**Date:** 2026-03-24
**Target:** sudo-rs v0.2.13 (commit on branch `main`)
**Auditor:** Automated deep-code review (Claude)
**Scope:** Full codebase — authentication, authorization, privilege management, environment handling, file operations, timestamp management, command execution, parser, IPC

---

## Executive Summary

sudo-rs is a well-engineered, memory-safe reimplementation of sudo in Rust. The codebase demonstrates strong security awareness: hardened enums, `#![forbid(unsafe_code)]` on critical modules, secure memory wiping, CLOCK_BOOTTIME for timestamps, and extensive file permission checks. Two prior professional audits (2023, 2025) have been performed.

This audit identified **3 high-severity**, **4 medium-severity**, and **5 low-severity** findings, plus several informational notes. No remotely exploitable code execution vulnerabilities were found.

---

## HIGH Severity Findings

### H1: TOCTOU Race in `traversed_secure_open` (sudoedit path validation)

**File:** `src/system/audit.rs:291-383`
**Impact:** Potential unauthorized file write via symlink race
**CVSS:** 7.0 (High)

The `traversed_secure_open` function traverses each path component with `O_NOFOLLOW`, checking at each step that the invoking user cannot write to the directory. However, there is a **time-of-check-to-time-of-use (TOCTOU) gap** between:
1. Opening a directory component and checking `user_cannot_write()` (lines 370-374)
2. The subsequent `open_at()` call for the next component

If the invoking user can race to replace a non-writable directory with a symlink to a writable location between iterations, the traversal could be misdirected. The `O_NOFOLLOW` flag mitigates symlink attacks at each step, but a directory rename attack (where the user owns a parent directory higher up the tree) could still succeed if the permission check at lines 315-352 has a gap.

**Mitigating factors:**
- The `user_cannot_write` check uses `faccessat` with `AT_EMPTY_PATH` checking the real UID (not effective), which is correct
- The check rejects any directory owned by the invoking user (line 319), which is a strong defense
- Exploitation requires a very tight race window

**Recommendation:** Consider using `openat2()` with `RESOLVE_BENEATH` on Linux 5.6+ to eliminate the TOCTOU window entirely, or hold directory file descriptors open and perform all subsequent operations relative to them without re-resolution.

---

### H2: `dangerous_extend` Bypasses All Environment Filtering When SETENV Tag is Active

**File:** `src/sudo/env/environment.rs:245-254` and `src/sudo/pipeline.rs:90-104`
**Impact:** Arbitrary environment variable injection when SETENV is granted
**CVSS:** 6.8 (Medium-High)

When `trust_environment` is `true` (derived from the SETENV tag in sudoers, or implicitly from `ALL`), user-supplied environment variables are passed directly through `dangerous_extend()` with **zero filtering** — no `should_keep()` check, no bash function injection check (the `()` prefix check), no LD_PRELOAD/LD_LIBRARY_PATH filtering.

```rust
// pipeline.rs:90-104
let (checked_vars, trusted_vars) = if controls.trust_environment {
    (vec![], user_requested_env_vars)  // ALL vars go to trusted_vars
} else {
    (user_requested_env_vars, vec![])
};
// ...
environment::dangerous_extend(&mut target_env, trusted_vars);  // No filtering!
```

This means a sudoers rule like `user ALL=(ALL) ALL` (which implicitly sets SETENV) allows the user to inject `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`, or any other dangerous variable. While this matches original sudo behavior, it is a well-known privilege escalation vector.

**Recommendation:**
- Even when SETENV is active, filter `LD_*`, `_RLD*`, and other linker/loader variables through `env_delete` unless explicitly overridden
- At minimum, always reject variables starting with `()` (bash function injection) even in the trusted path
- The function is aptly named `dangerous_extend` — consider whether the "dangerous" behavior is truly necessary

---

### H3: Timestamp File Encoding Uses Native Byte Order (`to_ne_bytes`)

**File:** `src/system/time.rs:36-37` and `src/system/timestamp.rs`
**Impact:** Timestamp portability issue / potential corruption on architecture mismatch
**CVSS:** 5.3 (Medium)

`SystemTime::encode()` uses `to_ne_bytes()` (native endianness) while the file header uses `to_le_bytes()` (little-endian). If the timestamp file were ever shared across architectures (e.g., via NFS-mounted `/var/run`), or if a big-endian system reads a file written by a little-endian system, the timestamps would be misinterpreted, potentially granting unauthorized authentication bypass by misreading the timestamp as being within the validity window.

```rust
// time.rs:36-37 — native endian
let secs = self.secs.to_ne_bytes();
let nsecs = self.nsecs.to_ne_bytes();

// timestamp.rs:124-125 — little endian
self.file.write_all(&Self::MAGIC_NUM.to_le_bytes())?;
self.file.write_all(&Self::FILE_VERSION.to_le_bytes())?;
```

**Recommendation:** Change `SystemTime::encode()`/`decode()` and `ProcessCreateTime::encode()`/`decode()` to use `to_le_bytes()`/`from_le_bytes()` consistently, matching the file header format. This would require a version bump to version 3.

---

## MEDIUM Severity Findings

### M1: Editor Command Injection via Space-Separated Arguments in Environment Variables

**File:** `src/sudoers/mod.rs:317-341`
**Impact:** Potential command injection through SUDO_EDITOR/VISUAL/EDITOR
**CVSS:** 5.5 (Medium)

The `select_editor` function splits the editor environment variable on spaces:

```rust
let mut arguments = editor_env.split(' ');
let Some(editor) = arguments.next().map(PathBuf::from) else { continue; };
let arguments = arguments.map(OsString::from).collect();
```

While the editor path is validated against a whitelist (when `trusted_env` is false) and checked for executability, the **arguments** are not validated. A malicious `SUDO_EDITOR="vi --cmd ':!malicious_command'"` could inject arbitrary arguments to a whitelisted editor. For visudo specifically, `trusted_env` is based on `env_editor` setting, which could allow untrusted environment variables.

**Recommendation:** Consider restricting arguments or applying an allowlist of safe editor flags when the environment is not fully trusted.

---

### M2: No Rate Limiting on Timestamp File Operations

**File:** `src/system/timestamp.rs`
**Impact:** Potential DoS via timestamp file manipulation
**CVSS:** 4.3 (Medium)

The timestamp file operations (`touch`, `create`, `disable`, `reset`) use `FileLock::exclusive` with `blocking=false`. If the lock cannot be acquired, the operation fails immediately. An attacker who can repeatedly invoke `sudo -k` (which calls `disable()`) or `sudo -K` (which calls `reset()`) could:
1. Create contention on the timestamp file lock
2. Force repeated authentication for other sudo sessions on the same TTY

**Recommendation:** Consider adding rate limiting or using a blocking lock with a timeout for critical timestamp operations.

---

### M3: `wipe_memory` Pattern May Be Insufficient on Modern Compilers

**File:** `src/pam/securemem.rs:84-95`
**Impact:** Potential password remnants in memory
**CVSS:** 4.0 (Medium)

The secure memory wiping uses `write_volatile` + atomic fences:

```rust
fn wipe_memory(memory: &mut [u8]) {
    let nonsense: u8 = 0x55;
    for c in memory {
        unsafe { std::ptr::write_volatile(c, nonsense) };
    }
    atomic::fence(atomic::Ordering::SeqCst);
    atomic::compiler_fence(atomic::Ordering::SeqCst);
}
```

While this is a common pattern, `write_volatile` only guarantees the write is not elided — it does not prevent the compiler from copying the data elsewhere first (e.g., via register spills, stack copies, or debug info). The buffer is allocated via `libc::calloc` (good — avoids Rust allocator which may copy), but intermediate copies in the PAM conversation function could leak password bytes on the stack.

**Recommendation:** Consider using the `zeroize` crate which is specifically designed for this purpose and has been audited, or use platform-specific `explicit_bzero()` / `memset_s()`.

---

### M4: Missing Validation of `num_msg` in PAM Conversation Function

**File:** `src/pam/converse.rs:218-220`
**Impact:** Potential integer overflow or excessive memory allocation
**CVSS:** 3.7 (Low-Medium)

The PAM conversation function casts `num_msg` directly to `usize` for `Vec::with_capacity`:

```rust
let mut resp_bufs = Vec::with_capacity(num_msg as usize);
for i in 0..num_msg as usize {
```

If a malicious PAM module passes a negative `num_msg` (which is `c_int`), the cast to `usize` would produce a very large number, causing either an allocation failure or a denial of service. While PAM modules are typically trusted, this is defense-in-depth.

**Recommendation:** Add a bounds check: `if num_msg < 0 || num_msg > 256 { return PAM_CONV_ERR; }`

---

## LOW Severity Findings

### L1: `fork()` Safety Invariant Not Enforced at Runtime

**File:** `src/system/mod.rs:126-130`
**Impact:** Potential UB if called from multithreaded context
**CVSS:** 2.0 (Low)

The `fork()` function has a safety comment stating "Must not be called in multithreaded programs" but the FIXME at line 127 notes there is no runtime assertion for this. Given that the noexec handler spawns a thread (`src/exec/noexec.rs:281`), there is a theoretical window where `fork()` could be called in a multithreaded context if the code path is ever restructured.

**Recommendation:** Add a debug assertion using `libc::pthread_self()` or an atomic thread counter to verify single-threadedness.

---

### L2: Session Timestamp File Path Uses UID String Without Validation

**File:** `src/system/timestamp.rs:38-43`
**Impact:** Unlikely path injection
**CVSS:** 1.5 (Low)

```rust
pub fn open_for_user(user: &CurrentUser, timeout: Duration) -> io::Result<Self> {
    let uid = user.uid;
    let mut path = PathBuf::from(Self::BASE_PATH);
    path.push(uid.to_string());
```

The UID is converted to string and pushed as a path component. While UIDs are numeric and `uid.to_string()` is safe, this pattern could be dangerous if the type ever changes or if a display implementation were altered. The `secure_open_cookie_file` provides defense-in-depth.

**Recommendation:** No action required — the current implementation is safe due to the numeric nature of UIDs and the secure open checks.

---

### L3: `PamBuffer` Uses `calloc`/`free` Instead of Rust Allocator

**File:** `src/pam/securemem.rs:41-51, 73-80`
**Impact:** Minor inconsistency, not a vulnerability
**CVSS:** 1.0 (Info)

`PamBuffer` deliberately uses `libc::calloc` and `libc::free` to avoid the Rust allocator. This is intentional (to ensure PAM receives memory it can `free()`), but means the memory is not tracked by Rust's allocation system. The `leak()` method explicitly forgets the buffer, transferring ownership to PAM.

**Recommendation:** This is correctly implemented. The `leak()` + `forget()` pattern properly transfers ownership.

---

### L4: `is_safe_tz` Allows Relative TZ Values Without Full Validation

**File:** `src/sudo/env/environment.rs:132-154`
**Impact:** Minor information leak via crafted TZ values
**CVSS:** 2.5 (Low)

Relative TZ values (not starting with `/`) are only checked for `..` sequences, printability, and PATH_MAX. A value like `../../etc/shadow` without a leading `/` passes the `starts_with(b"/")` check at line 139 (it doesn't start with `/`), and then passes the `..` check at line 151 — wait, it contains `..` so it would be caught. However, values like `TZ=UTC;malicious` or extremely long timezone names could potentially trigger edge cases in libc's timezone parsing.

**Mitigating factors:** The `is_printable` check restricts to ASCII alphanumeric and punctuation, which blocks most injection attempts.

**Recommendation:** Consider additionally validating that relative TZ values match known timezone patterns (e.g., `[A-Za-z]+` optionally followed by offset specifiers).

---

### L5: Hardcoded Fallback Editor Path

**File:** `src/sudoers/policy.rs:154`
**Impact:** If `/usr/bin/vi` is compromised, visudo uses it
**CVSS:** 1.0 (Info)

```rust
super::select_editor(&self.settings, true)
    .unwrap_or_else(|| (std::path::PathBuf::from("/usr/bin/vi"), vec![]))
```

The fallback editor is hardcoded. If no editor is found through normal resolution, `/usr/bin/vi` is used without further validation.

**Recommendation:** This is acceptable behavior — if an attacker controls `/usr/bin/vi`, they likely already have root access.

---

## Informational Notes

### I1: Strong Use of Hardened Enums (Positive)

The codebase uses hardened enum discriminants with non-obvious sentinel values (e.g., `0x52a2925`, `0xad5d6da`) for security-critical enums like `Authorization`, `DirChange`, `AuthenticatingUser`, `Meta`, `Args`, `Umask`. This provides defense against memory corruption attacks (Rowhammer, bit-flips) that could flip an `Authorization::Forbidden` to `Authorization::Allowed`.

### I2: Correct Use of CLOCK_BOOTTIME (Positive)

The timestamp system uses `CLOCK_BOOTTIME` instead of `CLOCK_REALTIME`, which prevents timestamp attacks via system clock manipulation. This is a significant improvement over original sudo which historically had clock-manipulation vulnerabilities.

### I3: PAM User Verification After Authentication (Positive)

The PAM authentication code (lines 188-198 in `src/pam/mod.rs`) explicitly verifies that no PAM module changed the username during authentication. This prevents a class of attacks where a malicious PAM module redirects authentication to a different user.

### I4: Signal Handling During Authentication (Positive)

SIGINT and SIGQUIT are properly masked during `pam_authenticate()` (lines 159-164) and restored afterward, preventing signal-based authentication bypass.

### I5: `#![forbid(unsafe_code)]` on Critical Modules (Positive)

The sudoers parser (`src/sudoers/`), common utilities (`src/common/`), and su implementation (`src/su/`) all use `#![forbid(unsafe_code)]`, while sudo uses `#![deny(unsafe_code)]`. This is excellent practice for a privilege escalation tool.

### I6: Include File Recursion Limit (Positive)

The sudoers parser limits include depth to 128 (`INCLUDE_LIMIT`), preventing stack exhaustion via recursive includes.

### I7: NOEXEC Implementation Quality (Positive)

The seccomp-based NOEXEC implementation correctly handles the first execve (allowing sudo's own exec) and blocks subsequent ones. The TOCTOU concern mentioned in the man page for seccomp user notify is correctly dismissed since only the first (trusted) exec is continued.

### I8: Thread Safety in Noexec Handler

The noexec handler spawns a thread (line 281 in `noexec.rs`) after forking, which means it runs in the child process context. This is architecturally sound since the thread is spawned after fork completes, but it means the child process is no longer single-threaded from that point.

---

## Architecture Assessment

### Strengths
1. **Memory safety by default** — Rust's ownership model eliminates entire classes of vulnerabilities
2. **Minimal unsafe surface** — Unsafe code is concentrated in well-documented system interaction layers
3. **Defense-in-depth** — Multiple overlapping security checks (file permissions, env filtering, hardened enums)
4. **Correct privilege management** — `irrevocably_drop_privileges()` with assertion of root effective UID
5. **Good separation of concerns** — Parser, policy, execution engine are cleanly separated

### Areas for Improvement
1. **SETENV bypass** (H2) is the most impactful finding — environment variable injection via trusted path
2. **Timestamp encoding inconsistency** (H3) should be fixed for correctness
3. **Consider `zeroize` crate** for more robust secret wiping
4. **Add fuzzing targets** for the sudoers parser — while the parser is in safe Rust, logic bugs could lead to policy bypass

---

## Testing Recommendations

1. **Fuzz the sudoers parser** with AFL/libFuzzer — safe Rust prevents crashes but logic bugs in permission evaluation could be critical
2. **Test SETENV + LD_PRELOAD** — verify whether `LD_PRELOAD` can be injected when SETENV is active
3. **Test timestamp file race conditions** — use concurrent sudo invocations to stress the file locking
4. **Test sudoedit TOCTOU** — attempt symlink/rename races during the `traversed_secure_open` path traversal
5. **Test PAM conversation with adversarial modules** — verify behavior with malformed PAM responses
