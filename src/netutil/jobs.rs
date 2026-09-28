//! Reversible network configuration steps persisted in a state file, so a
//! crashed session can be cleaned up on the next start.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::logging::Logger;

/// A command is an argv vector. Commands starting with `@` are handled
/// internally (see [`run_command`]).
pub type Command = Vec<String>;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct NetworkJob {
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apply: Command,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reset: Command,
}

#[derive(Serialize, Deserialize)]
struct JobState {
    jobs: Vec<NetworkJob>,
    #[serde(rename = "createdAt")]
    created_at: String,
}

pub fn cmd<I, S>(args: I) -> Command
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    args.into_iter().map(Into::into).collect()
}

pub fn save_jobs(path: &Path, jobs: &[NetworkJob]) -> Result<(), String> {
    let state = JobState {
        jobs: jobs.to_vec(),
        created_at: chrono::Local::now().to_rfc3339(),
    };
    let data = serde_json::to_vec_pretty(&state).map_err(|e| e.to_string())?;
    std::fs::write(path, data).map_err(|e| e.to_string())
}

fn load_jobs(path: &Path) -> Result<Option<Vec<NetworkJob>>, String> {
    match std::fs::read(path) {
        Ok(data) => serde_json::from_slice::<JobState>(&data)
            .map(|s| Some(s.jobs))
            .map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Runs a command, returning its combined output.
pub fn run_command(argv: &[String]) -> Result<String, String> {
    let Some((prog, args)) = argv.split_first() else {
        return Ok(String::new());
    };
    if let Some(internal) = prog.strip_prefix('@') {
        return crate::sysnet::run_internal(internal, args).map(|_| String::new());
    }

    let mut c = std::process::Command::new(prog);
    c.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        c.creation_flags(CREATE_NO_WINDOW);
    }
    let out = c.output().map_err(|e| format!("{prog}: {e}"))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    if out.status.success() {
        Ok(text)
    } else {
        Err(format!("{} ({})", text.trim(), out.status))
    }
}

/// Executes each job's apply command in order. Rolls back on failure.
pub fn apply_jobs(logger: &Logger, path: &Path) -> Result<(), String> {
    let Some(jobs) = load_jobs(path).map_err(|e| format!("failed to load state: {e}"))? else {
        return Ok(());
    };
    for job in &jobs {
        if job.apply.is_empty() {
            continue;
        }
        if let Err(e) = run_command(&job.apply) {
            reset_jobs(logger, path);
            return Err(format!("job {:?}: {e}", job.description));
        }
    }
    Ok(())
}

/// Executes reset commands in reverse order and deletes the state file.
/// A missing state file is a no-op, so this is safe to call at start-up.
pub fn reset_jobs(logger: &Logger, path: &Path) {
    let jobs = match load_jobs(path) {
        Ok(Some(jobs)) => jobs,
        Ok(None) => return,
        Err(e) => {
            warn!(logger, ["err" => e], "failed to load network state");
            return;
        }
    };
    for job in jobs.iter().rev() {
        if job.reset.is_empty() {
            continue;
        }
        if let Err(e) = run_command(&job.reset) {
            warn!(logger, ["err" => e, "cmd" => job.reset.join(" ")], "reset command failed (ignored)");
        }
    }
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(logger, ["err" => e], "failed to delete network state file");
        }
    }
}
