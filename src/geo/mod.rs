//! Geo IP query module.
//!
//! Provides IP geolocation queries using ip-api.com.

mod query;
mod utils;

pub use query::{query_geo_batch, query_geo_single, GeoError};
pub use utils::country_to_flag;
