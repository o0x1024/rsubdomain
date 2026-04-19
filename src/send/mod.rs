mod error;
mod query;
mod sender;

pub use error::SendDogError;
pub use query::build_dns_query;
pub use sender::{generate_flag_index_from_map, generate_map_index, SendDog};
