/// PostgreSQL integration (enabled when the `postgres-integration` feature is active).
#[cfg(feature = "postgres-integration")]
pub mod inner {
    use crate::config::PostgresConfig;
    use sqlx::PgPool;
    use tracing::{info, warn};

    pub struct PostgresClient {
        pool: Option<PgPool>,
    }

    impl PostgresClient {
        pub async fn new(config: &PostgresConfig) -> Self {
            let pool = if let Some(url) = &config.url {
                match sqlx::postgres::PgPoolOptions::new()
                    .max_connections(config.max_connections)
                    .connect(url)
                    .await
                {
                    Ok(p) => {
                        info!("PostgreSQL pool created");
                        Some(p)
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to connect to PostgreSQL");
                        None
                    }
                }
            } else {
                None
            };
            PostgresClient { pool }
        }

        pub fn is_available(&self) -> bool {
            self.pool.is_some()
        }

        pub async fn ping(&self) -> bool {
            let Some(ref pool) = self.pool else {
                return false;
            };
            sqlx::query("SELECT 1").execute(pool).await.is_ok()
        }
    }
}

#[cfg(not(feature = "postgres-integration"))]
pub mod inner {
    use crate::config::PostgresConfig;

    pub struct PostgresClient;

    impl PostgresClient {
        pub async fn new(_config: &PostgresConfig) -> Self {
            PostgresClient
        }
        pub fn is_available(&self) -> bool {
            false
        }
        pub async fn ping(&self) -> bool {
            false
        }
    }
}

#[allow(unused_imports)]
pub use inner::PostgresClient;
