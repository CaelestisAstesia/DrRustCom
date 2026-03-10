//! 会话引擎模块 (Session Engine)
//!
//! 本模块定义了对外暴露的顶级接口 [`AuthSession`]。
//! 它集成了配置管理、网络通信、协议策略与状态监控。

use std::sync::Arc;
use tokio::sync::watch;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::config::DrcomConfig;
use crate::error::{DrcomError, Result};
use crate::network::NetworkClient;
use crate::protocol::v520d::strategy::Strategy520D;
use crate::state::{create_shared_state, CoreStatus, SharedState};

/// Dr.COM 认证会话引擎
pub struct AuthSession {
    config: Arc<DrcomConfig>,
    pub state: SharedState,
    network: Option<Arc<NetworkClient>>,
    status_tx: watch::Sender<(CoreStatus, String)>,
    pub status_rx: watch::Receiver<(CoreStatus, String)>,
}

impl AuthSession {
    pub fn new(config: DrcomConfig) -> Self {
        debug!("正在初始化 AuthSession 引擎...");
        let (tx, rx) = watch::channel((CoreStatus::Idle, "Ready".to_string()));
        Self {
            config: Arc::new(config),
            state: create_shared_state(),
            network: None,
            status_tx: tx,
            status_rx: rx,
        }
    }

    fn update_status(&self, status: CoreStatus, msg: impl Into<String>) {
        let msg = msg.into();
        self.state.write().unwrap().status = status;
        let _ = self.status_tx.send((status, msg.clone()));

        match status {
            CoreStatus::Error => error!("[{:?}] {}", status, msg),
            CoreStatus::Offline => warn!("[{:?}] {}", status, msg),
            _ => info!("[{:?}] {}", status, msg),
        }
    }

    /// 内部助手：确保网络客户端已初始化
    async fn ensure_network(&mut self) -> Result<()> {
        if self.network.is_none() {
            let net = NetworkClient::connect(
                self.config.bind_ip,
                self.config.server_address,
                self.config.server_port,
            )
            .await?;
            self.network = Some(Arc::new(net));
            debug!("Network underlying ready");
        }
        Ok(())
    }

    /// 执行完整的认证流程
    #[instrument(skip(self), name = "auth_login")]
    pub async fn login(&mut self) -> Result<()> {
        // 解耦：网络初始化逻辑
        self.ensure_network().await?;

        self.update_status(CoreStatus::Connecting, "Authenticating...");

        let network = self.network.as_ref().unwrap();
        let strategy = Strategy520D::new(&self.config, network, self.state.clone());

        // 2. 执行 Challenge
        if let Err(e) = strategy.challenge().await {
            self.update_status(CoreStatus::Error, format!("Challenge failed: {}", e));
            return Err(e);
        }

        // 3. 执行 Login
        match strategy.login().await {
            Ok(_) => {
                self.update_status(CoreStatus::LoggedIn, "Login Success");
                Ok(())
            }
            Err(e) => {
                let status = if let DrcomError::Auth(_) = e {
                    CoreStatus::Offline
                } else {
                    CoreStatus::Error
                };
                self.update_status(status, format!("Login Failed: {}", e));
                Err(e)
            }
        }
    }

    /// [Core API] 脉冲 (Pulse)
    pub async fn pulse(&mut self) -> Result<()> {
        // 1. 检查在线状态与防重入锁
        {
            let st = self.state.read().unwrap();
            if !st.is_online() {
                return Err(DrcomError::State("Pulse denied: Session is offline".into()));
            }
            // 防重入：如果状态正处于 Connecting（例如正在登录或执行关键握手），跳过本次脉冲
            if st.status == CoreStatus::Connecting {
                warn!("A protocol operation is already in progress, skipping pulse tick.");
                return Ok(());
            }
        }

        // 2. 确保网络连接
        self.ensure_network().await?;
        let network = self.network.as_ref().unwrap();

        // 3. 调用策略层执行带重试的 keep_alive
        let strategy = Strategy520D::new(&self.config, network, self.state.clone());

        match strategy.keep_alive().await {
            Ok(_) => {
                let mut st = self.state.write().unwrap();
                if st.status == CoreStatus::LoggedIn {
                    st.status = CoreStatus::Heartbeat;
                    let _ = self.status_tx.send((CoreStatus::Heartbeat, "Alive".into()));
                }
                trace!("Pulse successful");
                Ok(())
            }
            Err(e) => {
                self.update_status(CoreStatus::Offline, format!("Pulse stopped: {}", e));
                Err(e)
            }
        }
    }

    pub async fn stop(&mut self) {
        info!("Stopping session...");
        if let Some(network) = &self.network {
            let strategy = Strategy520D::new(&self.config, network, self.state.clone());
            if let Err(e) = strategy.logout().await {
                warn!("Logout request failed: {}", e);
            }
        }
        self.update_status(CoreStatus::Offline, "Stopped");
    }
}
