use drrustcom::{AuthSession, CoreStatus, DrcomConfig};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::signal;
use tokio::time::{self, Duration};
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Layer};

/// 仅在应用层定义的映射函数，保持核心库纯净
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. 双图层日志配置
    let file_appender = tracing_appender::rolling::never(".", "debug.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // 控制台图层：只看 INFO
    let stdout_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .with_filter(EnvFilter::new("info"));

    // 文件图层：记录 DEBUG 细节
    let file_layer = fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_filter(EnvFilter::new("debug"));

    tracing_subscriber::registry()
        .with(stdout_layer)
        .with(file_layer)
        .init();

    info!("=== Dr.COM Rust Debug Monitor (Controlled Pulse Mode) ===");

    // 实时统计数据
    let heartbeat_count = Arc::new(AtomicU64::new(0));
    let start_time = Instant::now();

    // 加载配置并初始化会话
    let config = DrcomConfig::from_toml_file("config.toml")?;
    let mut session = AuthSession::new(config);
    let mut status_rx = session.status_rx.clone();

    // 2. 状态监听任务：负责在状态变更时输出日志
    let hb_count_clone = Arc::clone(&heartbeat_count);
    tokio::spawn(async move {
        while status_rx.changed().await.is_ok() {
            let (status, msg) = {
                let data = status_rx.borrow();
                (data.0, data.1.clone())
            };

            let status_cn = status_to_cn(status);
            match status {
                CoreStatus::Offline | CoreStatus::Error => {
                    error!(status = ?status, "警报: {} - {}", status_cn, msg);
                }
                _ => info!("状态迁移: [{}] -> {}", status_cn, msg),
            }
        }
    });

    // 3. 执行登录与脉冲循环
    match session.login().await {
        Ok(_) => {
            info!("登录成功。进入 20s 周期循环...");

            let mut interval = time::interval(Duration::from_secs(20));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // 发射一次脉冲（内置自动重试补偿）
                        if let Err(e) = session.pulse().await {
                            error!("脉冲彻底中断: {}", e);
                            break;
                        }

                        // 更新并显示实时统计
                        let count = hb_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
                        let uptime = start_time.elapsed();

                        info!(
                            "脉冲正常 | 计数: {} | 运行时间: {:02}h:{:02}m",
                            count,
                            uptime.as_secs() / 3600,
                            (uptime.as_secs() % 3600) / 60
                        );
                    }
                    _ = signal::ctrl_c() => {
                        warn!("接收到中断信号，准备安全退出...");
                        break;
                    }
                }
            }

            // 注销并清理
            session.stop().await;
            info!("测试结束。总挂机时长: {:?}", start_time.elapsed());
        }
        Err(e) => {
            error!("初始认证失败: {}", e);
        }
    }

    Ok(())
}
