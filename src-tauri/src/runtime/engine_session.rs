use super::*;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Runtime {
    pub(super) async fn start_engine(
        self: &Arc<Self>,
        link: &Arc<Link>,
        peer: &Identity,
        address: std::net::IpAddr,
    ) -> Result<()> {
        let _lifecycle = self.start_stop.lock().await;
        let mut guard = self.engine.lock().await;
        ensure!(self.current(link), "共享会话已结束");
        ensure!(guard.is_none(), "上一份引擎尚未退出");
        let (mut c, dir, id) = {
            let i = self.inner.lock().await;
            (
                i.state.config.clone(),
                i.store.directory.clone(),
                i.state.device_id.clone(),
            )
        };
        if c.role == "client" {
            c.shortcut = peer.shortcut.clone();
            c.modifier_mapping = peer.modifier_mapping;
            c.clipboard = peer.clipboard;
            c.clipboard_megabytes = peer.clipboard_megabytes;
            c.deskflow_port = peer.deskflow_port;
            c.layout_side = peer.layout_side.clone();
            c.cross_screen_video = peer.cross_screen_video.clone();
        }
        let settings = engine::prepare(&c, &id, peer, &dir, &address.to_string())?;
        let binary = self.binary(&c)?;
        let (tx, mut rx) = mpsc::channel(64);
        let (transitions, mut changes) = mpsc::channel(32);
        let engine = Engine::start(
            binary.clone(),
            &c,
            &settings,
            &dir,
            &self.platform.resources,
            tx,
        )
        .await?;
        if !engine.emergency_watch_active() {
            // The in-app Tauri emergency shortcut still works; only the
            // separate watchdog process is missing.
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            self.log("error", "独立紧急停止监听未能启动，仅应用内紧急快捷键可用")
                .await;
        }
        self.trace("engine.started", json!({"pid":engine.pid(),"guardianPid":engine.guardian_pid(),"parentPid":std::process::id(),"binary":binary,"session":link.id,"version":env!("CARGO_PKG_VERSION")})).await;
        *guard = Some(engine);
        {
            let mut i = self.inner.lock().await;
            if self.current(link) {
                i.state.engine = "starting".into();
            }
        }
        self.publish();
        drop(guard);
        // P0-1 heartbeat watchdog: every engine IPC/output event counts
        // as activity (see emergency.rs for what it can and cannot prove).
        // On trip, closing the session runs the existing session-end path,
        // which stops the engine and restores local input.
        let watchdog = Arc::new(std::sync::Mutex::new(crate::emergency::Watchdog::new(
            c.emergency_timeout_secs,
        )));
        watchdog
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .start(now_ms());
        let watchdog_events = watchdog.clone();
        let watchdog_tick = watchdog.clone();
        let this = self.clone();
        let context = link.clone();
        tokio::spawn(async move {
            while let Some(change) = changes.recv().await {
                if !this.current(&context) {
                    break;
                }
                this.observe_transition(&context, change).await;
            }
        });
        let this = self.clone();
        let context = link.clone();
        let expected = peer.fingerprint.clone();
        let host = c.role == "host";
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if !this.current(&context) {
                    break;
                }
                watchdog_events
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .activity(now_ms());
                match event {
                    engine::Event::Ipc(line) => {
                        if line == "observerDisconnected" {
                            this.log("error", "引擎状态通道已断开，已停止本次共享")
                                .await;
                            context.session.close();
                            break;
                        }
                        if let Some(actual) = line.strip_prefix("peerFingerprint=") {
                            if actual.replace(':', "").to_lowercase() != expected {
                                this.log("error", "引擎连接证书与配对身份不一致，已停止共享")
                                    .await;
                                context.session.close();
                                break;
                            }
                        }
                        if line == "connectionState=Connected" {
                            {
                                let mut i = this.inner.lock().await;
                                if this.current(&context) {
                                    i.state.engine = "ready".into();
                                    // P0-2: a session that demonstrably
                                    // captured input proves the engine grant
                                    // for the rest of this app run.
                                    i.engine_tcc.reached_ready = true;
                                    i.engine_tcc.permission_error = false;
                                }
                            }
                            this.publish();
                        } else if line.starts_with("connectionState=") {
                            {
                                let mut i = this.inner.lock().await;
                                if this.current(&context) {
                                    i.state.engine = "starting".into();
                                }
                            }
                            this.publish();
                        }
                        this.trace("engine.ipc", json!({"line":line})).await;
                    }
                    engine::Event::Output(line) => {
                        let lower = line.to_lowercase();
                        if lower.contains("fingerprint does not match")
                            || lower.contains("failed to verify") && lower.contains("fingerprint")
                        {
                            this.log("error", "引擎证书校验失败，已停止共享").await;
                            context.session.close();
                            break;
                        }
                        if host {
                            if let Some(change) = parse_transition(&line) {
                                let _ = this.observed.send((context.id, change.clone()));
                                if transitions.try_send(change).is_err() {
                                    context.session.close();
                                    break;
                                }
                            }
                        }
                        // P0-2: permission-class engine output is surfaced
                        // distinctly instead of drowning in the generic
                        // "check permissions" advice. The upstream clipboard
                        // filter in engine.rs may drop lines mentioning
                        // clipboard before they reach here; that filter is
                        // intentionally left untouched (another audit item).
                        if crate::engine_tcc::matches_permission_error(&line) {
                            {
                                let mut i = this.inner.lock().await;
                                if this.current(&context) {
                                    i.engine_tcc.permission_error = true;
                                }
                            }
                            this.log("error", &format!("检测到引擎权限类错误：{line}"))
                                .await;
                        } else if (lower.contains("failed")
                            || lower.contains("cannot")
                            || lower.contains("error"))
                            && !lower.contains("screenbridge-probe")
                        {
                            this.diagnostic_line(&line).await;
                        }
                    }
                    engine::Event::Exited(reason) => {
                        {
                            let mut i = this.inner.lock().await;
                            if this.current(&context) {
                                i.state.engine = "error".into();
                            }
                        }
                        this.log("error", &format!("键鼠引擎已退出：{reason}"))
                            .await;
                        context.session.close();
                        break;
                    }
                }
            }
        });
        let this = self.clone();
        let context = link.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                if !this.current(&context) {
                    break;
                }
                let trip = watchdog_tick
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .tick(now_ms());
                if trip.is_some() {
                    this.log("error", "引擎心跳超时，已自动停止共享并恢复本地输入；若画面仍停在对端，请用显示器实体按键切回").await;
                    context.session.close();
                    break;
                }
            }
        });
        let this = self.clone();
        let context = link.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(25)).await;
            if this.current(&context) && this.snapshot().await.engine != "ready" {
                this.log("error", "引擎连接超时，请检查两端权限、端口和诊断日志")
                    .await;
                context.session.close();
            }
        });
        Ok(())
    }
    pub(super) async fn diagnostic_line(&self, line: &str) {
        let mut i = self.inner.lock().await;
        let now = std::time::Instant::now();
        if let Some((last, count, when)) = &mut i.diagnostic_line {
            if last == line && now.duration_since(*when) < Duration::from_secs(5) {
                *count += 1;
                return;
            }
            let summary = (*count > 1).then(|| json!({"line":last,"count":count}));
            if let Some(summary) = summary {
                let _ = i.diagnostics.record("engine.repeated", summary);
            }
        }
        i.diagnostic_line = Some((line.into(), 1, now));
        drop(i);
        self.log("error", line).await;
    }
}
