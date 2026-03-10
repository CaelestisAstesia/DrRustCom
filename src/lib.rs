//! DrRustCom 核心库
//! 现代化、类型安全的 Dr.COM 认证协议核心库

pub mod config;
pub mod crypto;
pub mod error;
pub mod network;
pub mod protocol;
pub mod state;
pub mod session;

pub use error::{AuthErrorCode, DrcomError};
pub use state::{CoreStatus, DrcomState};
pub use session::AuthSession;
