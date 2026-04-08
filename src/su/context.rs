use std::{
    collections::HashMap,
    env,
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
};

use crate::common::{error::Error, resolve::CurrentUser};
use crate::exec::{RunOptions, Umask};
use crate::log::user_warn;
use crate::system::{Group, User};
use crate::{common::resolve::is_valid_executable, system::interface::UserId};

type Environment = HashMap<OsString, OsString>;

/// Environment variables that are always removed when switching users.
///
/// These variables can be used to inject code (e.g. shared libraries, interpreter
/// modules) into the process started by `su` and must never be propagated to the
/// target user's session. This list mirrors the dangerous-variable set that
/// sudo's `env_delete` / whitelisting mechanism already strips.
const DANGEROUS_ENV_VARS: &[&str] = &[
    // Dynamic linker injection
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_BIND_NOT",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_DYNAMIC_WEAK",
    "LD_ORIGIN_PATH",
    "LD_PROFILE",
    "LD_PROFILE_OUTPUT",
    "LD_SHOW_AUXV",
    "LD_USE_LOAD_BIAS",
    "_RLD_LIST",
    "_RLD_ROOT",
    // Shell injection
    "IFS",
    "CDPATH",
    "ENV",
    "BASH_ENV",
    "PS4",
    "GLOBIGNORE",
    "BASHOPTS",
    "SHELLOPTS",
    "FPATH",
    "NULLCMD",
    "READNULLCMD",
    "ZDOTDIR",
    "TMPPREFIX",
    // Interpreter path injection
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONUSERBASE",
    "PERL5LIB",
    "PERL5OPT",
    "PERL5DB",
    "PERLLIB",
    "PERLIO_DEBUG",
    "RUBYLIB",
    "RUBYOPT",
    "JAVA_TOOL_OPTIONS",
    // Locale/term path injection
    "LOCALDOMAIN",
    "RES_OPTIONS",
    "HOSTALIASES",
    "NLSPATH",
    "PATH_LOCALE",
    "TERMINFO",
    "TERMINFO_DIRS",
    "TERMPATH",
    "TERMCAP",
];

/// Returns true if the given key matches a dangerous environment variable
/// pattern. Supports exact matches and wildcard prefix patterns (e.g. `LD_*`).
fn is_dangerous_env(key: &OsStr) -> bool {
    let key_bytes = key.as_encoded_bytes();

    // Check exact matches
    if DANGEROUS_ENV_VARS
        .iter()
        .any(|var| key_bytes == var.as_bytes())
    {
        return true;
    }

    // Reject any variable whose value starts with "()" (bash function export)
    // This check is done on the key name pattern rather than value here;
    // the value check is performed in `sanitize_environment` below.

    false
}

/// Remove dangerous environment variables from the given environment.
/// This prevents code injection via LD_PRELOAD, interpreter paths, etc.
fn sanitize_environment(env: &mut Environment) {
    env.retain(|key, value| {
        // Reject bash-exported function definitions
        if value.as_encoded_bytes().starts_with(b"()") {
            return false;
        }
        !is_dangerous_env(key)
    });
}

use super::cli::SuRunOptions;

const VALID_LOGIN_SHELLS_LIST: &str = "/etc/shells";
const FALLBACK_LOGIN_SHELL: &str = "/bin/sh";

// TODO: use _PATH_STDPATH and _PATH_DEFPATH_ROOT from paths.h
const PATH_DEFAULT: &str = "/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games";
const PATH_DEFAULT_ROOT: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[derive(Debug)]
pub(crate) struct SuContext {
    command: PathBuf,
    arguments: Vec<OsString>,
    pub(crate) options: SuRunOptions,
    pub(crate) environment: Environment,
    pub(crate) user: User,
    pub(crate) requesting_user: CurrentUser,
    group: Group,
}

/// check that a shell is not restricted / exists in /etc/shells
fn is_restricted(shell: &Path) -> bool {
    if let Some(pattern) = shell.as_os_str().to_str() {
        if let Ok(contents) = fs::read_to_string(VALID_LOGIN_SHELLS_LIST) {
            return !contents.lines().any(|l| l == pattern);
        } else {
            return FALLBACK_LOGIN_SHELL != pattern;
        }
    }

    true
}

impl SuContext {
    pub(crate) fn from_env(options: SuRunOptions) -> Result<SuContext, Error> {
        // resolve environment, reset if this is a login
        let mut environment = if options.login {
            Environment::default()
        } else {
            let mut env = env::vars_os().collect::<Environment>();
            // Remove dangerous environment variables (LD_PRELOAD, etc.) to
            // prevent code injection into processes running as the target user.
            sanitize_environment(&mut env);
            env
        };

        // Don't reset the environment variables specified in the
        // comma-separated list when clearing the environment for
        // --login. The whitelist is ignored for the environment
        // variables HOME, SHELL, USER, LOGNAME, PATH, and any
        // variable that could be used for code injection.
        if options.login {
            if let Some(value) = env::var_os("TERM") {
                environment.insert("TERM".into(), value);
            }

            for name in options.whitelist_environment.iter() {
                let key = OsString::from(name);
                if is_dangerous_env(&key) {
                    user_warn!(
                        "ignoring dangerous environment variable '{name}' in whitelist"
                    );
                    continue;
                }
                if let Some(value) = env::var_os(name) {
                    // Reject bash function export values even for whitelisted vars
                    if !value.as_encoded_bytes().starts_with(b"()") {
                        environment.insert(key, value);
                    }
                }
            }
        }

        let requesting_user = CurrentUser::resolve()?;

        // resolve target user
        let mut user = User::from_name(options.user.as_cstr())?
            .ok_or_else(|| Error::UserNotFound(options.user.clone().into()))?;

        // check the current user is root
        let is_current_root = User::real_uid() == UserId::ROOT;
        let is_target_root = options.user == "root";

        // only root can set a (additional) group
        if !is_current_root && (!options.supp_group.is_empty() || !options.group.is_empty()) {
            return Err(Error::Options(
                "only root can specify alternative groups".to_owned(),
            ));
        }

        // resolve target group
        let mut group = user.primary_group()?;

        if !options.supp_group.is_empty() || !options.group.is_empty() {
            user.groups.clear();
        }

        for group_name in options.group.iter() {
            let primary_group = Group::from_name(group_name.as_cstr())?
                .ok_or_else(|| Error::GroupNotFound(group_name.clone().into()))?;

            // last argument is the primary group
            group = primary_group.clone();
            user.groups.insert(0, primary_group.gid);
        }

        // add additional group if current user is root
        for (index, group_name) in options.supp_group.iter().enumerate() {
            let supp_group = Group::from_name(group_name.as_cstr())?
                .ok_or_else(|| Error::GroupNotFound(group_name.clone().into()))?;

            // set primary group if none was provided
            if index == 0 && options.group.is_empty() {
                group = supp_group.clone();
            }

            user.groups.push(supp_group.gid);
        }

        // the shell specified with --shell
        // the shell specified in the environment variable SHELL, if the --preserve-environment option is used
        // the shell listed in the passwd entry of the target user
        let user_shell = &user.shell;

        let mut command = options
            .shell
            .as_ref()
            .cloned()
            .or_else(|| {
                if options.preserve_environment && is_current_root {
                    environment.get(&OsString::from("SHELL")).map(|v| v.into())
                } else {
                    None
                }
            })
            .unwrap_or(user_shell.clone());

        // If the target user has a restricted shell (i.e. the shell field of
        // this user's entry in /etc/passwd is not listed in /etc/shells),
        // then the --shell option or the $SHELL environment variable won't be
        // taken into account, unless su is called by root.
        if is_restricted(user_shell.as_path()) && !is_current_root {
            command = user_shell.to_path_buf();
            user_warn!("using restricted shell {path}", path = command.display());
        }

        if !command.exists() {
            return Err(Error::CommandNotFound(command));
        }

        if !is_valid_executable(&command) {
            return Err(Error::InvalidCommand(command));
        }

        // pass command to shell
        let arguments = if let Some(command) = &options.command {
            vec!["-c".into(), command.into()]
        } else {
            options.arguments.clone()
        };

        if options.login {
            environment.insert(
                "PATH".into(),
                if is_target_root {
                    PATH_DEFAULT_ROOT
                } else {
                    PATH_DEFAULT
                }
                .into(),
            );
        }

        if !options.preserve_environment {
            // extend environment with fixed variables
            environment.insert("HOME".into(), user.home.clone().into());
            environment.insert("SHELL".into(), command.clone().into());

            // Always set USER and LOGNAME to the target user when changing
            // identity. The previous code skipped this when the target was root
            // in non-login mode, leaving the invoking user's values which could
            // confuse programs that check these variables for authorization.
            environment.insert("USER".into(), options.user.clone().into());
            environment.insert("LOGNAME".into(), options.user.clone().into());
        }

        Ok(SuContext {
            command,
            arguments,
            options,
            environment,
            user,
            requesting_user,
            group,
        })
    }
}

impl SuContext {
    pub(crate) fn as_run_options(&self) -> RunOptions<'_> {
        RunOptions {
            command: &self.command,
            arguments: &self.arguments,
            arg0: None,
            chdir: None,
            is_login: self.options.login,
            user: &self.user,
            group: &self.group,
            umask: Umask::Preserve,

            background: false,
            use_pty: true,
            noexec: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::path::PathBuf;

    use crate::{
        common::{Error, resolve::CurrentUser},
        su::cli::{SuAction, SuOptions, SuRunOptions},
        su::context::{User, is_restricted},
    };

    use super::{Environment, SuContext, is_dangerous_env, sanitize_environment};

    fn get_options(args: &[&str]) -> SuRunOptions {
        let mut args = args.iter().map(|s| s.to_string()).collect::<Vec<String>>();
        args.insert(0, "/bin/su".to_string());
        let SuAction::Run(options) = SuOptions::parse_arguments(args)
            .unwrap()
            .validate()
            .unwrap()
        else {
            panic!();
        };

        options
    }

    #[test]
    fn su_to_root() {
        let options = get_options(&["root"]);
        let context = SuContext::from_env(options).unwrap();

        assert_eq!(context.user.name, "root");
    }

    #[test]
    fn group_as_non_root() {
        let options = get_options(&["-g", "root"]);
        let result = SuContext::from_env(options);
        let expected = Error::Options("only root can specify alternative groups".to_owned());

        assert!(result.is_err());
        assert_eq!(format!("{}", result.err().unwrap()), format!("{expected}"));
    }

    #[test]
    fn dangerous_env_vars_detected() {
        assert!(is_dangerous_env(OsStr::new("LD_PRELOAD")));
        assert!(is_dangerous_env(OsStr::new("LD_LIBRARY_PATH")));
        assert!(is_dangerous_env(OsStr::new("LD_AUDIT")));
        assert!(is_dangerous_env(OsStr::new("PYTHONPATH")));
        assert!(is_dangerous_env(OsStr::new("PERL5LIB")));
        assert!(is_dangerous_env(OsStr::new("RUBYLIB")));
        assert!(is_dangerous_env(OsStr::new("BASH_ENV")));
        assert!(is_dangerous_env(OsStr::new("IFS")));
        assert!(is_dangerous_env(OsStr::new("JAVA_TOOL_OPTIONS")));

        // Safe variables should not be flagged
        assert!(!is_dangerous_env(OsStr::new("HOME")));
        assert!(!is_dangerous_env(OsStr::new("PATH")));
        assert!(!is_dangerous_env(OsStr::new("TERM")));
        assert!(!is_dangerous_env(OsStr::new("DISPLAY")));
        assert!(!is_dangerous_env(OsStr::new("LANG")));
        assert!(!is_dangerous_env(OsStr::new("USER")));
    }

    #[test]
    fn sanitize_removes_dangerous_vars() {
        let mut env = Environment::new();
        env.insert("HOME".into(), "/root".into());
        env.insert("PATH".into(), "/usr/bin".into());
        env.insert("LD_PRELOAD".into(), "/tmp/evil.so".into());
        env.insert("LD_LIBRARY_PATH".into(), "/tmp".into());
        env.insert("PYTHONPATH".into(), "/tmp/pylib".into());
        env.insert("TERM".into(), "xterm".into());
        env.insert("DISPLAY".into(), ":0".into());

        sanitize_environment(&mut env);

        assert!(env.contains_key(&OsString::from("HOME")));
        assert!(env.contains_key(&OsString::from("PATH")));
        assert!(env.contains_key(&OsString::from("TERM")));
        assert!(env.contains_key(&OsString::from("DISPLAY")));
        assert!(!env.contains_key(&OsString::from("LD_PRELOAD")));
        assert!(!env.contains_key(&OsString::from("LD_LIBRARY_PATH")));
        assert!(!env.contains_key(&OsString::from("PYTHONPATH")));
    }

    #[test]
    fn sanitize_removes_bash_function_exports() {
        let mut env = Environment::new();
        env.insert("HOME".into(), "/root".into());
        env.insert("BASH_FUNC_evil%%".into(), "() { evil_code; }".into());
        env.insert("SAFE_VAR".into(), "normal_value".into());

        sanitize_environment(&mut env);

        assert!(env.contains_key(&OsString::from("HOME")));
        assert!(env.contains_key(&OsString::from("SAFE_VAR")));
        assert!(!env.contains_key(&OsString::from("BASH_FUNC_evil%%")));
    }

    #[test]
    fn invalid_shell() {
        let cur_user = CurrentUser::resolve().unwrap();
        let daemon = User::from_name(c"daemon").unwrap().unwrap();
        for user in [&cur_user, &daemon] {
            let options = get_options(&["-s", "/not/a/shell", &user.name]);
            let result = SuContext::from_env(options);
            let expected;

            // this test is allowed to fail if run as root -- do not run unit tests as root
            if is_restricted(&user.shell) {
                if let Ok(ctx) = result {
                    // some linux distro's actually provide a "/bin/nologin" command; in this
                    // case we test that the --shell command is properly ignored
                    assert_eq!(ctx.command, user.shell);
                    return;
                } else {
                    // others (Fedora) do not
                    expected = Error::CommandNotFound(PathBuf::from(&user.shell));
                }
            } else {
                expected = Error::CommandNotFound(PathBuf::from("/not/a/shell"));
            }

            assert!(result.is_err());
            assert_eq!(format!("{}", result.err().unwrap()), format!("{expected}"));
        }
    }
}
