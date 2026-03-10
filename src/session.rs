use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

use crate::config::DrcomConfig;
use crate::error::{DrcomError, Result};
use crate::network::NetworkClient;
use crate::protocol::v520d::strategy::Strategy520D;
use crate::state::{create_shared_state, CoreStatus, SharedState};

/// Dr.COM 认证会话引擎 (等同于 Python 版的 DrcomCore)
pub struct AuthSession {
    /// 引用计数的配置对象，允许跨线程共享
    config: Arc<DrcomConfig>,
    /// 线程安全的共享状态机
    pub state: SharedState,
    /// 异步网络客户端 (在 login 时初始化)
    network: Option<Arc<NetworkClient>>,
    /// 后台心跳守护任务的句柄
    heartbeat_task: Option<JoinHandle<()>>,
    /// 状态变更发送端
    status_tx: watch::Sender<(CoreStatus, String)>,
    /// 状态变更接收端 (供外部 GUI 或控制台订阅监听)
    pub status_rx: watch::Receiver<(CoreStatus, String)>,
}

impl AuthSession {
    /// 实例化一个新的认证会话
    pub fn new(config: DrcomConfig) -> Self {
        // 创建一个初始状态的 watch 通道
        let (tx, rx) = watch::channel((CoreStatus::Idle, "引擎已就绪".to_string()));

        Self {
            config: Arc::new(config),
            state: create_shared_state(),
            network: None,
            heartbeat_task: None,
            status_tx: tx,
            status_rx: rx,
        }
    }

    /// 内部方法：更新状态并广播给所有监听者
    fn update_status(&self, status: CoreStatus, msg: impl Into<String>) {
        let msg = msg.into();
        self.state.write().unwrap().status = status;
        // 广播新状态，任何持有 status_rx 的订阅者都会收到通知
        let _ = self.status_tx.send((status, msg.clone()));
        info!("[{:?}] {}", status, msg);
    }

    /// 执行完整的登录流程 (包含 Challenge 和 Login)
    pub async fn login(&mut self) -> Result<()> {
        self.update_status(CoreStatus::Connecting, "正在初始化网络并连接...");

        // 1. 惰性初始化网络客户端
        if self.network.is_none() {
            let net = NetworkClient::connect(
                self.config.bind_ip,
                self.config.server_address,
                self.config.server_port,
            )
            .await?;
            self.network = Some(Arc::new(net));
        }

        let network = self.network.as_ref().unwrap();
        let strategy = Strategy520D::new(&self.config, network, self.state.clone());

        // 2. 执行 Challenge
        if let Err(e) = strategy.challenge().await {
            self.update_status(CoreStatus::Error, format!("握手失败: {}", e));
            return Err(e);
        }

        // 3. 执行 Login
        match strategy.login().await {
            Ok(_) => {
                self.update_status(CoreStatus::LoggedIn, "登录成功");
                Ok(())
            }
            Err(e) => {
                // 如果是认证拒绝 (如密码错误)，标记为 Offline；如果是系统级错误，标记为 Error
                if let DrcomError::Auth(_) = e {
                    self.update_status(CoreStatus::Offline, format!("登录被拒绝: {}", e));
                } else {
                    self.update_status(CoreStatus::Error, format!("登录异常: {}", e));
                }
                Err(e)
            }
        }
    }

    /// 启动后台心跳守护任务
    pub fn start_heartbeat(&mut self) {
        if self.heartbeat_task.is_some() {
            warn!("心跳任务已在运行，请勿重复启动");
            return;
        }

        let current_status = self.state.read().unwrap().status;
        if current_status != CoreStatus::LoggedIn {
            error!("无法启动心跳：未处于 LoggedIn 状态");
            return;
        }

        self.update_status(CoreStatus::Heartbeat, "心跳维持中");

        // 克隆必要的引用，移交给后台 Task
        let config_clone = Arc::clone(&self.config);
        let network_clone = Arc::clone(self.network.as_ref().expect("网络未初始化"));
        let state_clone = self.state.clone();
        let status_tx_clone = self.status_tx.clone();

        // 派生 Tokio 异步任务 (脱离当前控制流在后台独立运行)
        let handle = tokio::spawn(async move {
            let strategy = Strategy520D::new(&config_clone, &network_clone, state_clone.clone());

            loop {
                // 每隔 20 秒执行一次心跳
                sleep(Duration::from_secs(20)).await;

                if let Err(e) = strategy.keep_alive().await {
                    error!("心跳失败: {}", e);
                    state_clone.write().unwrap().status = CoreStatus::Offline;
                    let _ = status_tx_clone.send((CoreStatus::Offline, "心跳丢失，已掉线".into()));
                    break; // 退出心跳循环
                }
            }
        });

        self.heartbeat_task = Some(handle);
    }

    /// 停止心跳，发送注销包，清理会话
    pub async fn stop(&mut self) {
        // 1. 暴力终止后台心跳任务
        if let Some(task) = self.heartbeat_task.take() {
            task.abort();
            info!("已终止后台心跳守护任务");
        }

        // 2. 尝试发送注销包
        if let Some(network) = &self.network {
            let strategy = Strategy520D::new(&self.config, network, self.state.clone());
            if let Err(e) = strategy.logout().await {
                warn!("注销过程异常: {}", e);
            }
        }

        self.update_status(CoreStatus::Offline, "已停止并注销");
    }
}
