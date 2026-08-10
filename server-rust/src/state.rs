//! Shared, cheaply-cloneable application state passed to each connection.

use crate::auth::AuthService;
use crate::config::Config;
use crate::ippool::IpPool;
use crate::session::SessionManager;
use crate::split::SplitPolicy;
use crate::sso::SsoVerifier;
use crate::tun::TunHandle;
use std::sync::Arc;

pub struct SharedState {
    pub config: Config,
    pub auth: Arc<AuthService>,
    pub ip_pool: Arc<IpPool>,
    pub sessions: Arc<SessionManager>,
    pub split: Arc<SplitPolicy>,
    /// OIDC id_token verifier; `None` when SSO is disabled (`OIDC_ISSUER` unset).
    pub sso: Option<Arc<SsoVerifier>>,
    pub tun: TunHandle,
}
