//! 会话引擎模块 (Session Engine)
//!
//! 本模块定义了对外暴露的顶级接口 [`AuthSession`]。
//! 它集成了配置管理、网络通信、协议策略与状态监控。
//!
//! 本版本遵循“受控引擎”范式，取消了隐式的后台任务，由应用层通过 [`pulse`] 驱动保活。

use std::sync::Arc;
use tokio::sync::watch;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::config::DrcomConfig;
use crate::error::{DrcomError, Result};
use crate::network::NetworkClient;
use crate::protocol::v520d::strategy::Strategy520D;
use crate::state::{create_shared_state, CoreStatus, SharedState};

/// Dr.COM 认证会话引擎
///
/// 负责管理认证会话的完整生命周期。
/// 采用事件驱动架构，通过 `status_rx` 广播状态变更。
pub struct AuthSession {
    /// 引用计数的配置对象
    config: Arc<DrcomConfig>,
    /// 线程安全的共享状态机
    pub state: SharedState,
    /// 异步网络客户端，在首次调用 [`login`] 时惰性初始化
    network: Option<Arc<NetworkClient>>,
    /// 状态变更发送端
    status_tx: watch::Sender<(CoreStatus, String)>,
    /// 状态变更接收端 (供外部订阅监听)
    pub status_rx: watch::Receiver<(CoreStatus, String)>,
}

impl AuthSession {
    /// 实例化一个新的认证会话
    ///
    /// ### 参数
    /// * `config`: 已加载的 [`DrcomConfig`] 配置对象
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

    /// 内部助手：原子化更新状态并向所有订阅者广播变更
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

    /// 执行完整的认证流程
    ///
    /// 包含网络初始化、Challenge 握手以及 Login 登录。
    #[instrument(skip(self), name = "auth_login")]
    pub async fn login(&mut self) -> Result<()> {
        self.update_status(CoreStatus::Connecting, "Initializing network...");

        // 1. 惰性初始化网络客户端
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
    ///
    /// 向服务器发射一次高可靠性的保活脉冲。
    /// 建议由外部定时器（如每 20 秒）驱动调用。
    ///
    /// ### Returns
    /// * `Ok(())`: 脉冲发射成功，链路状态正常。
    /// * `Err(e)`: 脉冲彻底失败，状态已自动切至 Offline。
    pub async fn pulse(&mut self) -> Result<()> {
        // 1. 检查在线状态
        {
            let st = self.state.read().unwrap();
            if !st.is_online() {
                return Err(DrcomError::State("Pulse denied: Session is offline".into()));
            }
        }

        // 2. 检查网络初始化
        let network = self.network.as_ref().ok_or_else(|| {
            error!("Pulse failed: Network not initialized");
            DrcomError::State("Network uninitialized".into())
        })?;

        // 3. 调用策略层执行带重试的 keep_alive
        let strategy = Strategy520D::new(&self.config, network, self.state.clone());

        match strategy.keep_alive().await {
            Ok(_) => {
                // 如果是首次脉冲，将状态从 LoggedIn 提升至 Heartbeat
                let mut st = self.state.write().unwrap();
                if st.status == CoreStatus::LoggedIn {
                    st.status = CoreStatus::Heartbeat;
                    let _ = self.status_tx.send((CoreStatus::Heartbeat, "Alive".into()));
                }
                trace!("Pulse successful");
                Ok(())
            }
            Err(e) => {
                // 脉冲彻底失败，执行掉线迁移
                self.update_status(CoreStatus::Offline, format!("Pulse stopped: {}", e));
                Err(e)
            }
        }
    }

    /// 停止会话并注销
    ///
    /// 发送注销报文并清空本地凭据。
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
