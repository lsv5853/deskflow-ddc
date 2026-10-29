//! macOS engine-binary TCC verdicts (P0-2).
//!
//! The problem: on macOS, the app-level check (`AXIsProcessTrusted()` in the
//! `mac-hotkey` helper) only proves that *this app's helper* holds
//! accessibility permission. It says nothing about the bundled `deskflow-core`
//! binary, which needs its own Input Monitoring / Accessibility grant to
//! capture input. Users who grant the app and still cannot move the mouse
//! hit exactly this gap.
//!
//! macOS offers no public API to ask "is binary X granted TCC permission",
//! so this module never claims certainty it does not have. It combines the
//! signals that do exist and reports one of four verdicts:
//!
//! - `Granted`: a session actually reached engine-ready. Only a session that
//!   demonstrably captured input proves the engine grant.
//! - `Denied`: a permission-error signature was seen in engine output (or in
//!   a probe run). This blocks starting a session and cannot be skipped.
//! - `Unknown`: no evidence either way (engine never ran, or no usable
//!   signal). Starting is intercepted, but the user may explicitly
//!   acknowledge and proceed.
//! - `NotApplicable`: anything that is not macOS.
//!
//! Deliberate non-goals, all documented as honest limits:
//! - Binary executability (`--help` probe) NEVER upgrades `Unknown` to
//!   `Granted`: a binary that runs is not a binary that may capture input.
//! - A verdict is sticky within one app run. TCC grants persist on the
//!   machine, so a grant observed earlier this run stays valid; a later
//!   revocation surfaces as a fresh permission error in the next session.
//! - Engine log lines containing "clipboard" are dropped upstream in
//!   `engine.rs` before they reach the session loop, so a permission error
//!   that mentions clipboard would not be seen here. That filter belongs to
//!   another audit item and is intentionally left untouched.

/// Verdict for the engine binary's macOS input-capture grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineTccVerdict {
    Granted,
    Denied,
    Unknown,
    NotApplicable,
}

impl EngineTccVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            EngineTccVerdict::Granted => "granted",
            EngineTccVerdict::Denied => "denied",
            EngineTccVerdict::Unknown => "unknown",
            EngineTccVerdict::NotApplicable => "notApplicable",
        }
    }
}

/// Signals accumulated while the app runs. Kept in runtime state, never
/// persisted: a fresh app launch starts at `Unknown` again.
#[derive(Clone, Copy, Debug, Default)]
pub struct EngineTccSignals {
    /// A session reached engine-ready (`connectionState=Connected`), which
    /// means the engine demonstrably captured input.
    pub reached_ready: bool,
    /// A permission-error signature was seen in engine output.
    pub permission_error: bool,
}

/// Pure decision table. `is_macos` is a parameter (instead of `cfg!`) so the
/// table itself is unit-testable on any host.
pub fn decide(signals: EngineTccSignals, is_macos: bool) -> EngineTccVerdict {
    if !is_macos {
        return EngineTccVerdict::NotApplicable;
    }
    // A permission error after the last ready wins: revocation or a tap that
    // broke mid-session must not hide behind an earlier success. The session
    // loop clears `permission_error` when it observes a fresh ready, so a
    // stale error cannot linger past a demonstrably working session.
    if signals.permission_error {
        return EngineTccVerdict::Denied;
    }
    if signals.reached_ready {
        return EngineTccVerdict::Granted;
    }
    EngineTccVerdict::Unknown
}

/// Start-gate outcome. `Denied` can never be skipped: starting anyway would
/// just reproduce the failure. `Unknown` may proceed only after the user
/// explicitly acknowledges the intercept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    Allow,
    BlockDenied,
    BlockUnknown,
}

pub fn gate(verdict: EngineTccVerdict, acknowledged: bool) -> Gate {
    match verdict {
        EngineTccVerdict::Granted | EngineTccVerdict::NotApplicable => Gate::Allow,
        EngineTccVerdict::Denied => Gate::BlockDenied,
        EngineTccVerdict::Unknown => {
            if acknowledged {
                Gate::Allow
            } else {
                Gate::BlockUnknown
            }
        }
    }
}

/// Permission-error signatures in engine output. Deliberately narrow: bare
/// words like "failed" or "error" are NOT enough, so unrelated failures
/// (certificate mismatch, connection refused, probe handshakes) never match.
/// Matching is case-insensitive and substring-based because Deskflow's exact
/// wording varies across versions; every match is reported with the original
/// line attached so a false positive is visible, not silent.
const PERMISSION_SIGNATURES: &[&str] = &[
    "permission",
    "accessibility",
    "event tap",
    // Compact form, e.g. the API name `CGEventTapCreate` in log lines.
    "eventtap",
    "assistive",
    "not trusted",
    "not permitted",
    "authorization",
    "input monitoring",
    "kaxerror",
    "tcc",
];

pub fn matches_permission_error(line: &str) -> bool {
    let lower = line.to_lowercase();
    PERMISSION_SIGNATURES.iter().any(|sig| lower.contains(sig))
}

/// Scan combined probe output (stdout + stderr) for a permission signature.
/// Used by the `--help` probe: a match upgrades the verdict to `Denied`;
/// clean output upgrades nothing.
pub fn probe_found_permission_error(combined_output: &str) -> bool {
    combined_output.lines().any(matches_permission_error)
}

/// Wizard text shown when starting is blocked by a `Denied` verdict.
/// Names the exact binary file the user must add; the app-level grant is a
/// different entry and does not cover this file.
pub fn wizard_text(binary_path: &str) -> String {
    format!(
        "检测到 Deskflow 引擎缺少输入监控授权，无法开始共享。\n\
         请在“系统设置 → 隐私与安全性 → 辅助功能”与“输入监控”中手动添加下面这个引擎文件（不是本应用本身）：\n\
         {binary_path}\n\
         添加后回到本应用点“重新检测”，检测通过后再开始共享。\n\
         注意：只给本应用授权是不够的，引擎文件必须单独出现在这两处授权列表里。"
    )
}

/// Intercept text shown when the verdict is `Unknown` and the user has not
/// acknowledged it yet.
pub fn intercept_text() -> &'static str {
    "引擎授权状态无法确定：本应用还没有证据证明内置引擎拿到了输入监控授权，\
     直接开始共享可能出现键鼠动不了的情况。\
     请先点“重新检测”（跑过一次共享并成功连接后状态会变为已授权），\
     或在引擎权限行点“我已了解，仍要开始”确认后重试。"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_signatures_match_realistic_engine_lines() {
        for line in [
            "ERROR: Failed to create event tap, check accessibility permission",
            "CGEventTapCreate failed: not permitted",
            "accessibility permission denied for process",
            "kAXErrorFailure while requesting assistive access",
            "TCC deny: input monitoring not granted",
            "Authorization required: please grant Input Monitoring",
        ] {
            assert!(matches_permission_error(line), "should match: {line}");
        }
    }

    #[test]
    fn permission_signatures_reject_unrelated_failures() {
        for line in [
            "fingerprint does not match",
            "failed to verify peer certificate",
            "connection refused on 127.0.0.1:24801",
            "hello=screenbridge-probe",
            "observerDisconnected",
            "clipboard size 4MB",
            "server started, listening on port 24801",
        ] {
            assert!(!matches_permission_error(line), "must not match: {line}");
        }
    }

    #[test]
    fn decision_table_covers_all_signal_combinations() {
        // Not macOS: always not applicable, whatever the signals say.
        for signals in [
            EngineTccSignals {
                reached_ready: false,
                permission_error: false,
            },
            EngineTccSignals {
                reached_ready: true,
                permission_error: false,
            },
            EngineTccSignals {
                reached_ready: false,
                permission_error: true,
            },
            EngineTccSignals {
                reached_ready: true,
                permission_error: true,
            },
        ] {
            assert_eq!(decide(signals, false), EngineTccVerdict::NotApplicable);
        }
        // macOS: permission error wins over an earlier ready.
        assert_eq!(
            decide(
                EngineTccSignals {
                    reached_ready: false,
                    permission_error: false
                },
                true
            ),
            EngineTccVerdict::Unknown
        );
        assert_eq!(
            decide(
                EngineTccSignals {
                    reached_ready: true,
                    permission_error: false
                },
                true
            ),
            EngineTccVerdict::Granted
        );
        assert_eq!(
            decide(
                EngineTccSignals {
                    reached_ready: false,
                    permission_error: true
                },
                true
            ),
            EngineTccVerdict::Denied
        );
        assert_eq!(
            decide(
                EngineTccSignals {
                    reached_ready: true,
                    permission_error: true
                },
                true
            ),
            EngineTccVerdict::Denied
        );
    }

    #[test]
    fn gate_never_skips_denied_but_allows_acknowledged_unknown() {
        assert_eq!(gate(EngineTccVerdict::Granted, false), Gate::Allow);
        assert_eq!(gate(EngineTccVerdict::Granted, true), Gate::Allow);
        assert_eq!(gate(EngineTccVerdict::NotApplicable, false), Gate::Allow);
        assert_eq!(gate(EngineTccVerdict::Denied, false), Gate::BlockDenied);
        assert_eq!(gate(EngineTccVerdict::Denied, true), Gate::BlockDenied);
        assert_eq!(gate(EngineTccVerdict::Unknown, false), Gate::BlockUnknown);
        assert_eq!(gate(EngineTccVerdict::Unknown, true), Gate::Allow);
    }

    #[test]
    fn probe_scan_only_denies_on_permission_signature() {
        assert!(probe_found_permission_error(
            "deskflow-core 1.27.0\nERROR: accessibility permission denied\n"
        ));
        assert!(!probe_found_permission_error(
            "deskflow-core 1.27.0\nUsage: deskflow-core [options]\n"
        ));
        assert!(!probe_found_permission_error(""));
    }

    #[test]
    fn wizard_text_names_the_exact_binary() {
        let text = wizard_text(
            "/Users/demo/Library/Application Support/app/engine/1.27.0-abc/runtime/core",
        );
        assert!(text.contains(
            "/Users/demo/Library/Application Support/app/engine/1.27.0-abc/runtime/core"
        ));
        assert!(text.contains("输入监控"));
        assert!(text.contains("重新检测"));
    }
}
