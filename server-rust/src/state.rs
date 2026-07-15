//! Shared, cheaply-cloneable application state passed to each connection.

use crate::auth::AuthService;
use crate::config::Config;
use crate::ippool::IpPool;
use crate::session::SessionManager;
use crate::tun::TunHandle;
use std::sync::Arc;

pub struct SharedState {
    pub config: Config,
    pub auth: Arc<AuthService>,
    pub ip_pool: Arc<IpPool>,
    pub sessions: Arc<SessionManager>,
    pub tun: TunHandle,
}
