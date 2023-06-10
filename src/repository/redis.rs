use crate::config::config::Config;
use crate::repository::redis::MobcError::{RedisCMDError, RedisPoolError, RedisTypeError};
use log::error;
use mobc::{Connection, Pool};
use mobc_redis::redis::Commands;
use mobc_redis::{
    redis,
    redis::{AsyncCommands, FromRedisValue},
    RedisConnectionManager,
};
use std::time::Duration;
use thiserror::Error;

pub type MobcPool = Pool<RedisConnectionManager>;
pub type MobcConn = Connection<RedisConnectionManager>;
type Result<T> = std::result::Result<T, Error>;

pub struct Redis {
    pool: MobcPool,
}

const CACHE_POOL_MAX_OPEN: u64 = 16;
const CACHE_POOL_MAX_IDLE: u64 = 8;
const CACHE_POOL_TIMEOUT_SECONDS: u64 = 1;
const CACHE_POOL_EXPIRE_SECONDS: u64 = 60;

#[derive(Error, Debug)]
pub enum Error {
    #[error("mobc error: {0}")]
    MobcError(#[from] MobcError),
}

#[derive(Error, Debug)]
pub enum MobcError {
    #[error("could not get redis connection from pool : {0}")]
    RedisPoolError(mobc::Error<redis::RedisError>),
    #[error("error parsing string from redis result: {0}")]
    RedisTypeError(redis::RedisError),
    #[error("error executing redis command: {0}")]
    RedisCMDError(redis::RedisError),
    #[error("error creating Redis client: {0}")]
    RedisClientError(redis::RedisError),
}

impl Redis {
    pub fn new(config: Config) -> Self {
        let client = redis::Client::open(config.redis_url)
            .map_err(MobcError::RedisClientError)
            .expect("Failed to create open redis client");
        let manager = RedisConnectionManager::new(client);
        let pool = Pool::builder()
            .get_timeout(Some(Duration::from_secs(CACHE_POOL_TIMEOUT_SECONDS)))
            .max_open(CACHE_POOL_MAX_OPEN)
            .max_idle(CACHE_POOL_MAX_IDLE)
            .max_lifetime(Some(Duration::from_secs(CACHE_POOL_EXPIRE_SECONDS)))
            .build(manager);

        Redis { pool }
    }

    async fn get_conn(&self) -> Result<MobcConn> {
        self.pool.get().await.map_err(|e| {
            eprintln!("error connecting to redis: {}", e);
            RedisPoolError(e).into()
        })
    }

    pub async fn set_str(&self, key: &str, value: &str, ttl_seconds: usize) -> Result<()> {
        let mut con = self.get_conn().await?;
        con.set(key, value).await.map_err(RedisCMDError)?;
        if ttl_seconds > 0 {
            con.expire(key, ttl_seconds).await.map_err(RedisCMDError)?;
        }
        Ok(())
    }

    pub async fn get_str(&self, key: &str) -> Result<String> {
        let mut con = self.get_conn().await?;
        let value = con.get(key).await.map_err(RedisCMDError)?;
        FromRedisValue::from_redis_value(&value).map_err(|e| RedisTypeError(e).into())
    }
}
