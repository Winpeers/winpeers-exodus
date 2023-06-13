use crate::config::config::Config;
use crate::repository::redis::DeadpoolError::{RedisCMDError, RedisPoolError};
use deadpool_redis::{redis::cmd, Config as RedisConfig, Connection, Pool, PoolError, Runtime};
use log::error;
use thiserror::Error;

type Result<T> = std::result::Result<T, Error>;

pub struct Redis {
    pool: Pool,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("deadpool error: {0}")]
    DeadpoolError(#[from] DeadpoolError),
}

#[derive(Error, Debug)]
pub enum DeadpoolError {
    #[error("could not get redis connection from pool : {0}")]
    RedisPoolError(PoolError),
    #[error("error executing redis command: {0}")]
    RedisCMDError(redis::RedisError),
}

impl Redis {
    pub fn new(config: Config) -> Self {
        let redis_config = RedisConfig::from_url(config.redis_url);
        let pool = redis_config.create_pool(Some(Runtime::Tokio1)).unwrap();
        Redis { pool }
    }

    async fn get_conn(&self) -> Result<Connection> {
        self.pool.get().await.map_err(|e| {
            error!("error connecting to redis: {}", e);
            RedisPoolError(e).into()
        })
    }

    pub async fn set_str(&self, key: &str, value: &str, ttl_seconds: usize) -> Result<()> {
        let mut conn = self.get_conn().await?;
        cmd("SETEX")
            .arg(key)
            .arg(ttl_seconds)
            .arg(value)
            .query_async(&mut conn)
            .await
            .map_err(RedisCMDError)?;
        Ok(())
    }

    pub async fn get_str(&self, key: &str) -> Result<String> {
        let mut conn = self.get_conn().await?;
        Ok(cmd("GET")
            .arg(key)
            .query_async(&mut conn)
            .await
            .map_err(RedisCMDError)?)
    }

    pub async fn delete_key(&self, key1: &str, key2: &str) -> Result<()> {
        let mut conn = self.get_conn().await?;
        cmd("DEL")
            .arg(&[key1, key2])
            .query_async(&mut conn)
            .await
            .map_err(RedisCMDError)?;
        Ok(())
    }
}
