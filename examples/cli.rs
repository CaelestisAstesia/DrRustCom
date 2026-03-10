use drrustcom::{DrcomConfig, AuthSession, CoreStatus};
use std::time::Instant;
use tokio::signal;
use tracing::{info, error};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

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
    // 日志审计配置
    let file_appender = tracing_appender::rolling::never(".", "debug.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env().add_directive(tracing::Level::DEBUG.into()))
        .with(fmt::layer().with_writer(std::io::stdout))
        .with(fmt::layer().with_writer(non_blocking).with_ansi(false))
        .init();

    info!("=== Dr.COM Rust Debug Monitor Started ===");
    let start_time = Instant::now();
    let mut heartbeat_count = 0u64;

    let config = DrcomConfig::from_toml_file("config.toml")?;
    let mut session = AuthSession::new(config);
    let mut status_rx = session.status_rx.clone();

    tokio::spawn(async move {
        while status_rx.changed().await.is_ok() {
            // 获取当前快照
            let (status, msg) = {
                let data = status_rx.borrow();
                (data.0, data.1.clone())
            };

            let status_cn = status_to_cn(status); // 在应用层转换

            match status {
                CoreStatus::Heartbeat => {
                    heartbeat_count += 1;
                    let uptime = start_time.elapsed();
                    info!(
                        "💓 [{}] Count: {} | Uptime: {}h {}m | Msg: {}",
                        status_cn, heartbeat_count, uptime.as_secs() / 3600, (uptime.as_secs() % 3600) / 60, msg
                    );
                },
                CoreStatus::Offline | CoreStatus::Error => {
                    // 使用 ? 语法在 tracing 中打印实现 Debug 的枚举
                    error!(status = ?status, "🚨 Alert: Session Interrupted! {} - {}", status_cn, msg);
                },
                _ => info!("🔄 State Transition: [{}] -> {}", status_cn, msg),
            }
        }
    });

    if session.login().await.is_ok() {
        session.start_heartbeat();
        signal::ctrl_c().await?;
        session.stop().await;
    }

    Ok(())
}
