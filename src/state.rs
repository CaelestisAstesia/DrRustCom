use std::sync::{Arc, RwLock};

/// 核心引擎的生命周期状态枚举。
///
/// 状态流转示意:
/// Idle -> Connecting -> LoggedIn -> Heartbeat -> Offline
///            |              |            |
///            v              v            v
///          Error          Error        Error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreStatus {
    /// 初始状态，引擎已实例化但未执行任何操作
    Idle,
    /// 正在连接中 (正在执行 Challenge 握手或 Login 登录)
    Connecting,
    /// 登录成功。已获取 Auth Info，但心跳任务尚未启动
    LoggedIn,
    /// 在线保活中。心跳守护任务正在后台稳定运行
    Heartbeat,
    /// 已离线。可能是用户主动注销，或因网络波动导致的心跳丢失
    Offline,
    /// 错误状态。发生了不可恢复的技术性错误
    Error,
}

/// 存储 Dr.COM 认证会话的易变状态数据。
/// 该对象是非持久化的，每次重新登录时建议重置。
#[derive(Debug)]
pub struct DrcomState {
    // --- 基础会话凭据 ---
    // 使用 Option 完美表达“尚未获取到数据”的空状态
    // [u8; 4] 和 [u8; 16] 保证了拿到的一定是定长合法数据
    pub salt: Option<[u8; 4]>,
    pub auth_info: Option<[u8; 16]>,

    // --- 引擎状态 ---
    pub status: CoreStatus,
    pub last_error: String,

    // --- D 版协议专用状态 ---
    pub keep_alive_serial_num: u8,
    pub keep_alive_tail: [u8; 4],
    pub ka2_initialized: bool,
}

impl DrcomState {
    /// 创建一个新的空状态
    pub fn new() -> Self {
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

    /// 判断当前是否处于“在线”状态。
    /// 在线状态包括 LoggedIn (刚登录) 和 Heartbeat (保活中)。
    pub fn is_online(&self) -> bool {
        matches!(self.status, CoreStatus::LoggedIn | CoreStatus::Heartbeat)
    }

    /// 重置会话凭据与状态机 (通常在掉线或重新登录时调用)
    pub fn reset(&mut self) {
        self.salt = None;
        self.auth_info = None;
        self.status = CoreStatus::Offline;
        self.keep_alive_serial_num = 0;
        self.keep_alive_tail = [0; 4];
        self.ka2_initialized = false;
    }
}

// =========================================================================
// 为外部系统提供的便利类型别名
// =========================================================================

/// 包装了并发安全读写锁的状态引用。
/// 这是提供给后台心跳任务和前台 GUI 共同持有的“通行证”。
pub type SharedState = Arc<RwLock<DrcomState>>;

/// 帮助快速创建一个并发安全的共享状态
pub fn create_shared_state() -> SharedState {
    Arc::new(RwLock::new(DrcomState::new()))
}
