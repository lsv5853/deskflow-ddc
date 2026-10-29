//! Emergency stop for a wedged Deskflow engine (P0-1).
//!
//! This module is deliberately dependency-free (only `std`) so its core logic
//! can be unit-tested with a bare `rustc --test`, without the Tauri stack.
//!
//! Two mechanisms, both independent of the engine's own input path:
//!
//! 1. An emergency hotkey. It is registered by the main application (Tauri
//!    global shortcut) and, on macOS/Windows, additionally by a separate
//!    watchdog process that owns no engine state. Pressing it kills the
//!    engine and lets the session close, which restores local input.
//! 2. A heartbeat watchdog. The session loop feeds every engine IPC/output
//!    event into [`Watchdog::activity`]; the engine task re-sends the same
//!    `hello=screenbridge-probe` handshake it already uses at connect, so a
//!    healthy engine answers at least once per probe interval. If no engine
//!    event arrives for longer than the configured timeout, the watchdog
//!    trips exactly once and the session stops the engine instead of
//!    silently hanging.
//!
//! Scope honesty, please keep this in mind when touching this file:
//! - The watchdog detects a *dead or IPC-silent* engine. It cannot prove
//!   that a live engine is forwarding input correctly; an input-layer wedge
//!   with a chatty IPC channel is still handled by the emergency hotkey
//!   (or by stopping from the peer computer).
//! - The watchdog assumes Deskflow's IPC server answers the `hello`
//!   handshake more than once. That is the same message the session already
//!   sends at connect, but it must be re-confirmed on real hardware for
//!   every Deskflow build we bundle. Setting the timeout to `0` disables
//!   the automatic trip (the hotkey channel keeps working).

/// Default emergency hotkey. It must not collide with the video-switch
/// shortcut (`control+alt+F10` by default), the engine's return-to-provider
/// key (`control+alt+Escape`), or the Windows-reserved F12.
pub const EMERGENCY_SHORTCUT_DEFAULT: &str = "control+alt+shift+F11";

/// Default heartbeat timeout, in seconds: three missed 5-second probes.
pub const EMERGENCY_TIMEOUT_DEFAULT_SECS: u64 = 15;

/// Probe interval used by the engine task, in seconds.
pub const EMERGENCY_PROBE_INTERVAL_SECS: u64 = 5;

/// A parsed `control+alt[(+shift)]+F<n>` hotkey.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hotkey {
    pub shift: bool,
    pub function: u8,
}

fn function_key_number(s: &str) -> Option<u8> {
    let digits = s.strip_prefix('F')?;
    if digits.is_empty() || digits.len() > 2 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u8 = digits.parse().ok()?;
    if (1..=17).contains(&n) {
        Some(n)
    } else {
        None
    }
}

/// Parse the hotkey syntax shared with the switch shortcut:
/// `control+alt+F<n>` or `control+alt+shift+F<n>`, F1..F17.
pub fn parse_hotkey(s: &str) -> Result<Hotkey, String> {
    let mut parts = s.split('+');
    if parts.next() != Some("control") || parts.next() != Some("alt") {
        return Err(format!("紧急快捷键格式无效：{s}"));
    }
    let mut shift = false;
    let mut function = None;
    for part in parts {
        if part == "shift" && !shift {
            shift = true;
        } else if function.is_none() {
            function = function_key_number(part);
            if function.is_none() {
                return Err(format!("紧急快捷键格式无效：{s}"));
            }
        } else {
            return Err(format!("紧急快捷键格式无效：{s}"));
        }
    }
    match function {
        Some(function) => Ok(Hotkey { shift, function }),
        None => Err(format!("紧急快捷键格式无效：{s}")),
    }
}

/// Validate an emergency hotkey against the switch shortcut and the
/// engine's built-in return keys. `windows_host` applies the Windows F12
/// reservation (the same rule as the switch shortcut).
pub fn validate_emergency_hotkey(
    emergency: &str,
    switch_shortcut: &str,
    windows_host: bool,
) -> Result<Hotkey, String> {
    let hotkey = parse_hotkey(emergency)?;
    if emergency == switch_shortcut {
        return Err("紧急快捷键不能与切换快捷键相同".into());
    }
    // Note: "control+alt+Escape" (the engine's return-to-provider key) is
    // already rejected by parse_hotkey, which only accepts F-keys.
    if windows_host && emergency.ends_with("F12") {
        return Err("Windows 无法注册 F12 全局快捷键".into());
    }
    Ok(hotkey)
}

/// Identity of a process used before killing it, mirroring the engine
/// guardian: a PID alone is not enough, because PIDs get reused. The
/// kernel start time must match the one recorded at spawn time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KillTarget {
    pub pid: u32,
    pub start_secs: u64,
    pub start_micros: u64,
}

impl KillTarget {
    /// True only when both the PID and the exact start time still match.
    /// A mismatch means the original process is gone (or the PID was
    /// recycled) and nothing must be killed.
    pub fn still_matches(&self, pid: u32, start_secs: u64, start_micros: u64) -> bool {
        self.pid > 1
            && self.pid == pid
            && self.start_secs == start_secs
            && self.start_micros == start_micros
    }
}

/// What the watchdog wants the session to do. It is returned at most once
/// per arming: after [`WatchdogAction::Trip`] the watchdog is spent until
/// it is started again, so a stuck session cannot spam kill requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchdogAction {
    Trip,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WatchdogState {
    Idle,
    Watching,
    Tripped,
    Stopped,
}

/// Tick-driven heartbeat watchdog. All time is supplied by the caller in
/// milliseconds so the logic is fully deterministic under test.
pub struct Watchdog {
    timeout_ms: u64,
    state: WatchdogState,
    last_activity_ms: u64,
}

impl Watchdog {
    /// `timeout_secs == 0` disables automatic tripping; the watchdog then
    /// never fires, but explicit emergency requests still work.
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            timeout_ms: timeout_secs.saturating_mul(1000),
            state: WatchdogState::Idle,
            last_activity_ms: 0,
        }
    }

    pub fn is_disabled(&self) -> bool {
        self.timeout_ms == 0
    }

    pub fn start(&mut self, now_ms: u64) {
        if self.is_disabled() {
            return;
        }
        self.state = WatchdogState::Watching;
        self.last_activity_ms = now_ms;
    }

    /// Record engine activity (any IPC line or engine output line).
    pub fn activity(&mut self, now_ms: u64) {
        if self.state == WatchdogState::Watching {
            self.last_activity_ms = now_ms;
        }
    }

    /// Advance the clock. Returns `Some(Trip)` exactly once, when the
    /// engine has been silent longer than the timeout.
    pub fn tick(&mut self, now_ms: u64) -> Option<WatchdogAction> {
        if self.state != WatchdogState::Watching || self.is_disabled() {
            return None;
        }
        if now_ms.saturating_sub(self.last_activity_ms) > self.timeout_ms {
            self.state = WatchdogState::Tripped;
            return Some(WatchdogAction::Trip);
        }
        None
    }

    /// An explicit emergency request (hotkey, tray, peer). It fires from
    /// Watching, and also from Tripped when the caller wants to force the
    /// kill again after the automatic trip; it never fires from Idle or
    /// Stopped, so a stray press cannot kill an engine that belongs to
    /// another session.
    pub fn emergency(&mut self) -> bool {
        matches!(self.state, WatchdogState::Watching | WatchdogState::Tripped)
    }

    /// Normal session end. After this, neither ticks nor emergency
    /// requests fire, so stopping the app never leaves a live watcher.
    pub fn stop(&mut self) {
        self.state = WatchdogState::Stopped;
    }

    pub fn is_watching(&self) -> bool {
        self.state == WatchdogState::Watching
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hotkey_syntax() {
        assert_eq!(
            parse_hotkey("control+alt+shift+F11").unwrap(),
            Hotkey {
                shift: true,
                function: 11
            }
        );
        assert_eq!(
            parse_hotkey("control+alt+F10").unwrap(),
            Hotkey {
                shift: false,
                function: 10
            }
        );
        for bad in [
            "",
            "control+F10",
            "alt+shift+F10",
            "control+alt+F18",
            "control+alt+F0",
            "control+alt+shift",
            "control+alt+shift+shift+F10",
            "control+alt+F10+extra",
            "control+alt+escape",
        ] {
            assert!(parse_hotkey(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn rejects_conflicting_emergency_hotkeys() {
        assert!(
            validate_emergency_hotkey("control+alt+shift+F11", "control+alt+F10", false).is_ok()
        );
        // Same as the switch shortcut.
        assert!(validate_emergency_hotkey("control+alt+F10", "control+alt+F10", false).is_err());
        // Engine return-to-provider key.
        assert!(validate_emergency_hotkey("control+alt+Escape", "control+alt+F10", false).is_err());
        // Windows F12 reservation.
        assert!(
            validate_emergency_hotkey("control+alt+shift+F12", "control+alt+F10", true).is_err()
        );
        assert!(
            validate_emergency_hotkey("control+alt+shift+F12", "control+alt+F10", false).is_ok()
        );
    }

    #[test]
    fn kill_target_requires_pid_and_start_time() {
        let target = KillTarget {
            pid: 4242,
            start_secs: 100,
            start_micros: 5,
        };
        assert!(target.still_matches(4242, 100, 5));
        assert!(!target.still_matches(4243, 100, 5)); // Different PID.
        assert!(!target.still_matches(4242, 101, 5)); // PID reused later.
        assert!(!target.still_matches(4242, 100, 6)); // Same second, later start.
        assert!(!KillTarget {
            pid: 1,
            start_secs: 100,
            start_micros: 5
        }
        .still_matches(1, 100, 5)); // Never kill PID 1.
    }

    #[test]
    fn healthy_heartbeat_never_trips() {
        let mut dog = Watchdog::new(15);
        dog.start(0);
        // Activity every 5 s (the probe interval) for two minutes.
        for now in (0..=120_000).step_by(5_000) {
            dog.activity(now);
            assert_eq!(dog.tick(now), None, "must not trip while active");
        }
        assert!(dog.is_watching());
    }

    #[test]
    fn heartbeat_timeout_trips_exactly_once_and_recovers_locally() {
        let mut dog = Watchdog::new(15);
        dog.start(0);
        dog.activity(5_000);
        assert_eq!(dog.tick(19_999), None); // 14_999 ms of silence: not yet.
        assert_eq!(dog.tick(20_001), Some(WatchdogAction::Trip)); // > 15 s.
        assert_eq!(dog.tick(120_000), None); // Never trips twice.
        assert!(!dog.is_watching());
    }

    #[test]
    fn emergency_works_even_when_ipc_is_already_dead() {
        // Scenario 3: the engine stopped answering, the watchdog already
        // tripped, and the user still hits the emergency hotkey.
        let mut dog = Watchdog::new(15);
        dog.start(0);
        dog.activity(0);
        assert_eq!(dog.tick(60_000), Some(WatchdogAction::Trip));
        assert!(dog.emergency(), "hotkey must still fire after a trip");
        // And from a healthy watching session too.
        let mut dog = Watchdog::new(15);
        dog.start(0);
        assert!(dog.emergency());
    }

    #[test]
    fn normal_stop_leaves_no_live_watcher() {
        let mut dog = Watchdog::new(15);
        dog.start(0);
        dog.stop();
        assert_eq!(dog.tick(600_000), None);
        assert!(!dog.emergency());
    }

    #[test]
    fn emergency_never_fires_without_a_session() {
        let mut dog = Watchdog::new(15);
        assert!(!dog.emergency(), "idle watchdog must not kill anything");
        assert_eq!(dog.tick(600_000), None);
    }

    #[test]
    fn zero_timeout_disables_auto_trip_but_keeps_hotkey() {
        let mut dog = Watchdog::new(0);
        assert!(dog.is_disabled());
        dog.start(0);
        assert_eq!(dog.tick(600_000), None);
        // start() is a no-op when disabled, so emergency() stays false:
        // a disabled watchdog owns no session. The hotkey path in the app
        // calls Runtime::emergency_stop directly instead.
        assert!(!dog.emergency());
    }
}
