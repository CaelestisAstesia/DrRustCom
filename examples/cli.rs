use drrustcom::{AuthSession, CoreStatus, DrcomConfig};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use std::env;
use std::io::{self, Read};
use tokio::signal;
use tokio::time::{self, Duration};
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Layer};

/// 仅在应用层定义的映射函数，将状态枚举转换为中文描述
fn status_to_cn(status: CoreStatus) -> &'static str {
    match status {
        CoreStatus::Idle => "闲置",
        CoreStatus::Connecting => "连接中",
        CoreStatus::LoggedIn => "已登录",
        CoreStatus::Heartbeat => "在线保活",
        CoreStatus::Offline => "离线",
        CoreStatus::Error => "错误",
    }
}

/// 辅助函数：在终端等待按键后退出，解决双击运行时闪退问题
fn pause_exit() {
    println!("\n按任意键退出程序...");
    let mut _unused = [0u8; 1];
    let _ = io::stdin().read(&mut _unused);
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. 获取程序运行目录
    let exe_path = env::current_exe()?;
    let exe_dir = exe_path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let config_path = exe_dir.join("config.toml");

    // 2. 日志配置：将日志存放在程序同级目录的 logs 文件夹下
    let log_dir = exe_dir.join("logs");
    let _ = std::fs::create_dir_all(&log_dir);
    let file_appender = tracing_appender::rolling::daily(log_dir, "drcom_debug.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let stdout_layer = fmt::layer().with_writer(io::stdout).with_filter(EnvFilter::new("info"));
    let file_layer = fmt::layer().with_writer(non_blocking).with_ansi(false).with_filter(EnvFilter::new("debug"));

    tracing_subscriber::registry().with(stdout_layer).with(file_layer).init();

    info!("=== Dr.COM Rust Client (Release Build) ===");

    // 3. 加载配置并校验
    let config = match DrcomConfig::from_toml_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("加载配置文件失败: {}. 请确保 'config.toml' 存在于程序同级目录。", e);
            pause_exit();
            return Ok(());
        }
    };

    let heartbeat_count = Arc::new(AtomicU64::new(0));
    let start_time = Instant::now();
    let mut session = AuthSession::new(config);
    let mut status_rx = session.status_rx.clone();

    // 4. 状态监听任务
    let hb_count_clone = Arc::clone(&heartbeat_count);
    tokio::spawn(async move {
        while status_rx.changed().await.is_ok() {
            let (status, msg) = {
                let data = status_rx.borrow();
                (data.0, data.1.clone())
            };
            let status_cn = status_to_cn(status); // 现在可以找到该函数了
            match status {
                CoreStatus::Offline | CoreStatus::Error => error!("状态异常: {} - {}", status_cn, msg),
                _ => info!("当前状态: [{}] -> {}", status_cn, msg),
            }
        }
    });

    // 5. 执行登录与脉冲循环
    match session.login().await {
        Ok(_) => {
            info!("认证成功，正在保持连接...");
            let mut interval = time::interval(Duration::from_secs(20));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = session.pulse().await {
                            error!("心跳链路中断: {}", e);
                            break;
                        }
                        let count = hb_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
                        let uptime = start_time.elapsed();
                        info!("保活中 | 计数: {} | 已运行: {:02}h:{:02}m",
                            count, uptime.as_secs() / 3600, (uptime.as_secs() % 3600) / 60);
                    }
                    _ = signal::ctrl_c() => {
                        warn!("接收到退出指令...");
                        break;
                    }
                }
            }
            session.stop().await;
        }
        Err(e) => {
            error!("认证彻底失败: {}", e);
        }
    }

    info!("程序已停止。");
    pause_exit();
    Ok(())
}
