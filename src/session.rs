//! 会话引擎模块 (Session Engine)
//!
//! 本模块定义了对外暴露的顶级接口 [`AuthSession`]。
//! 它集成了配置管理、网络通信、协议策略与状态监控，
//! 是构建 CLI、GUI 或服务守护进程的核心入口。

use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, instrument, trace, warn};

use crate::config::DrcomConfig;
use crate::error::{DrcomError, Result};
use crate::network::NetworkClient;
use crate::protocol::v520d::strategy::Strategy520D;
use crate::state::{create_shared_state, CoreStatus, SharedState};

/// Dr.COM 认证会话引擎
///
/// 负责管理认证会话的完整生命周期，包括网络初始化、双阶段认证、
/// 自动保活以及状态变更的实时广播。
///
///
pub struct AuthSession {
    /// 引用计数的配置对象，允许在后台任务中安全共享
    config: Arc<DrcomConfig>,
    /// 线程安全的共享状态机，存储当前的 Salt、Auth Info 等
    pub state: SharedState,
    /// 异步网络客户端，在首次调用 [`login`] 时惰性初始化
    network: Option<Arc<NetworkClient>>,
    /// 后台心跳守护任务的句柄，用于在注销时主动停止任务
    heartbeat_task: Option<JoinHandle<()>>,
    /// 状态变更发送端
    status_tx: watch::Sender<(CoreStatus, String)>,
    /// 状态变更接收端 (供外部订阅监听)
    ///
    /// 订阅者可以通过此频道获取实时的状态更新 (如从 `Connecting` 变为 `LoggedIn`)。
    pub status_rx: watch::Receiver<(CoreStatus, String)>,
}

impl AuthSession {
    /// 实例化一个新的认证会话
    ///
    /// ### 参数
    /// * `config`: 已加载的 [`DrcomConfig`] 配置对象
    pub fn new(config: DrcomConfig) -> Self {
        debug!("正在初始化 AuthSession 引擎...");

        // 初始化状态广播频道 (初始状态为 Idle)
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

    /// 内部助手：原子化更新状态并向所有订阅者广播变更
    fn update_status(&self, status: CoreStatus, msg: impl Into<String>) {
        let msg = msg.into();
        // 1. 更新共享内存中的状态
        self.state.write().unwrap().status = status;
        // 2. 广播至观察者频道
        let _ = self.status_tx.send((status, msg.clone()));

        // 根据严重程度选择日志级别
        match status {
            CoreStatus::Error => error!("[{:?}] {}", status, msg),
            CoreStatus::Offline => warn!("[{:?}] {}", status, msg),
            _ => info!("[{:?}] {}", status, msg),
        }
    }

    /// 执行完整的认证流程
    ///
    /// 该方法会依次执行：
    /// 1. 网络端口绑定
    /// 2. Challenge 握手以获取 Salt
    /// 3. Login 登录认证
    ///
    /// ### 错误
    /// 若任何阶段失败，将更新内部状态为 `Error` 或 `Offline` 并返回对应的 [`DrcomError`]。
    #[instrument(skip(self), name = "auth_login")]
    pub async fn login(&mut self) -> Result<()> {
        self.update_status(CoreStatus::Connecting, "正在初始化网络并连接...");

        // 1. 惰性初始化网络客户端 (若尚未连接)
        if self.network.is_none() {
            let net = NetworkClient::connect(
                self.config.bind_ip,
                self.config.server_address,
                self.config.server_port,
            )
            .await?;
            self.network = Some(Arc::new(net));
            debug!("网络底层已就绪");
        }

        let network = self.network.as_ref().unwrap();
        let strategy = Strategy520D::new(&self.config, network, self.state.clone());

        // 2. 执行 Challenge 阶段
        if let Err(e) = strategy.challenge().await {
            self.update_status(CoreStatus::Error, format!("握手失败: {}", e));
            return Err(e);
        }

        // 3. 执行 Login 阶段
        match strategy.login().await {
            Ok(_) => {
                self.update_status(CoreStatus::LoggedIn, "认证成功，已接入校园网");
                Ok(())
            }
            Err(e) => {
                let status = if let DrcomError::Auth(_) = e {
                    CoreStatus::Offline
                } else {
                    CoreStatus::Error
                };
                self.update_status(status, format!("登录异常: {}", e));
                Err(e)
            }
        }
    }

    /// 启动后台保活任务
    ///
    /// 此方法会派生 (Spawn) 一个异步 Task，每隔 20 秒执行一次保活心跳。
    /// 必须在 [`login`] 成功后调用。
    ///
    ///
    pub fn start_heartbeat(&mut self) {
        if self.heartbeat_task.is_some() {
            warn!("心跳守护任务已在运行，忽略重复启动请求");
            return;
        }

        // 状态检查
        {
            let current_status = self.state.read().unwrap().status;
            if current_status != CoreStatus::LoggedIn {
                error!(status = ?current_status, "非法调用：必须在 LoggedIn 状态下启动心跳");
                return;
            }
        }

        self.update_status(CoreStatus::Heartbeat, "心跳保活已启动");

        // 准备后台 Task 所需的克隆资源 (Arc)
        let config_clone = Arc::clone(&self.config);
        let network_clone = Arc::clone(self.network.as_ref().expect("逻辑错误：心跳启动时网络未初始化"));
        let state_clone = self.state.clone();
        let status_tx_clone = self.status_tx.clone();

        // 派生后台任务
        let handle = tokio::spawn(async move {
            debug!("后台心跳 Task 已进入运行态");
            let strategy = Strategy520D::new(&config_clone, &network_clone, state_clone.clone());

            loop {
                // 周期性休眠
                sleep(Duration::from_secs(20)).await;

                trace!("执行周期性心跳校验...");
                if let Err(e) = strategy.keep_alive().await {
                    error!("保活失败: {}", e);
                    // 原子化更新状态，触发外部观察者逻辑
                    let mut lock = state_clone.write().unwrap();
                    lock.status = CoreStatus::Offline;
                    let _ = status_tx_clone.send((CoreStatus::Offline, format!("心跳丢失: {}", e)));
                    break; // 链路中断，退出后台循环
                }
            }
            warn!("后台心跳 Task 已安全终结");
        });

        self.heartbeat_task = Some(handle);
    }

    /// 终止会话并注销
    ///
    /// 依次执行：停止后台任务 -> 发送注销报文 -> 重置本地状态。
    pub async fn stop(&mut self) {
        info!("正在优雅关闭认证会话...");

        // 1. 强力终止后台任务
        if let Some(task) = self.heartbeat_task.take() {
            task.abort();
            debug!("已停止后台保活守护进程");
        }

        // 2. 发送离线包 (Best Effort)
        if let Some(network) = &self.network {
            let strategy = Strategy520D::new(&self.config, network, self.state.clone());
            if let Err(e) = strategy.logout().await {
                warn!(error = ?e, "服务器注销请求发送失败 (可能已提前离线)");
            }
        }

        self.update_status(CoreStatus::Offline, "会话已完全停止");
    }
}
