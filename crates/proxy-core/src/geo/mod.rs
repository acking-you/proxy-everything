//! Geo IP query module.
//!
//! Provides IP geolocation queries using ip-api.com.

mod limiter;
mod query;
mod utils;

pub use query::{GeoError, ensure_db, is_local_network_host, query_geo_batch, query_geo_single};
pub use utils::country_to_flag;
