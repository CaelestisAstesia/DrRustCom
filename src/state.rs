//! 状态管理模块 (State Management)
//!
//! 本模块定义了 Dr.COM 认证引擎的核心生命周期状态及会话数据。
//! 采用 `Arc<RwLock<...>>` 实现线程安全的共享状态，支持后台心跳任务与前台监听者的并发访问。

use std::sync::{Arc, RwLock};
use tracing::{debug, info};

/// 核心引擎的生命周期状态枚举
///
/// 描述了从初始化到登录、保活以及异常掉线的完整生命周期。
///
///
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CoreStatus {
    /// 初始状态：引擎已实例化，尚未开始网络交互
    #[default]
    Idle,
    /// 正在连接：正在执行 Challenge 握手或 Login 登录封包交互
    Connecting,
    /// 登录成功：已获取服务器下发的 Auth Info 凭证，等待启动心跳
    LoggedIn,
    /// 在线保活：心跳守护任务 (Keep-Alive) 正在后台周期性运行
    Heartbeat,
    /// 已离线：用户主动注销或心跳丢失导致会话终止
    Offline,
    /// 错误状态：捕获到不可恢复的协议或网络异常
    Error,
}

/// 存储 Dr.COM 认证会话的易变状态数据
///
/// 该结构体包含了协议运行所需的临时凭证、序列号以及当前的运行状态。
/// 所有的协议字段都采用了定长数组（如 `[u8; 4]`）以确保内存布局与协议定义一致。
#[derive(Debug)]
pub struct DrcomState {
    // --- 基础会话凭据 ---
    /// 服务器下发的挑战盐值 (Salt)
    pub salt: Option<[u8; 4]>,
    /// 认证通过后获取的加密凭证 (Auth Info)
    pub auth_info: Option<[u8; 16]>,

    // --- 引擎运行信息 ---
    /// 当前生命周期状态
    pub status: CoreStatus,
    /// 最近一次发生的错误描述
    pub last_error: String,

    // --- D 版协议保活状态 ---
    /// 心跳包序列号 (0-255, 自动回绕)
    pub keep_alive_serial_num: u8,
    /// 服务器在心跳回包中下发的尾部校验数据
    pub keep_alive_tail: [u8; 4],
    /// 标识 KA2 (Type 1/3) 初始化序列是否已完成
    pub ka2_initialized: bool,
}

impl Default for DrcomState {
    fn default() -> Self {
        Self::new()
    }
}

impl DrcomState {
    /// 创建一个新的初始空状态
    pub fn new() -> Self {
        debug!("初始化 DrcomState 内存对象");
        Self {
            salt: None,
            auth_info: None,
            status: CoreStatus::Idle,
            last_error: String::new(),
            keep_alive_serial_num: 0,
            keep_alive_tail: [0; 4],
            ka2_initialized: false,
        }
    }

    /// 判断当前会话是否处于有效的在线状态
    ///
    /// 在线状态定义为：已成功登录 (`LoggedIn`) 或正在稳定保活 (`Heartbeat`)。
    pub fn is_online(&self) -> bool {
        matches!(self.status, CoreStatus::LoggedIn | CoreStatus::Heartbeat)
    }

    /// 重置会话凭据与状态机
    ///
    /// 通常在主动注销、检测到掉线或准备重新登录时调用。
    /// 调用后状态将迁移至 `Offline`，并清空所有临时凭证。
    pub fn reset(&mut self) {
        info!("重置会话状态：清空凭据并标记为离线");
        self.salt = None;
        self.auth_info = None;
        self.status = CoreStatus::Offline;
        self.keep_alive_serial_num = 0;
        self.keep_alive_tail = [0; 4];
        self.ka2_initialized = false;
    }
}

// =========================================================================
// 并发安全抽象
// =========================================================================

/// 线程安全的共享状态引用类型
///
/// 组合了 `Arc` (原子引用计数) 和 `RwLock` (读写锁)。
/// 后台任务通过此引用更新心跳数据，而前台 UI 可以并发地读取状态。
pub type SharedState = Arc<RwLock<DrcomState>>;

/// 创建一个全新的并发安全共享状态实例
pub fn create_shared_state() -> SharedState {
    Arc::new(RwLock::new(DrcomState::new()))
}
