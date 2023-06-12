// use crate::repository::redis::MobcError::{
//     RedisCMDError, RedisClientError, RedisPoolError, RedisTypeError,
// };
// // use crate::{MobcError::*, Result, REDIS_CON_STRING};
// use crate::config::config::Config;
// use mobc::{Connection, Pool};
// use mobc_redis::redis::{AsyncCommands, FromRedisValue};
// use mobc_redis::{redis, RedisConnectionManager};
// use std::time::Duration;
// use thiserror::Error;
//
// pub type MobcPool = Pool<RedisConnectionManager>;
// pub type MobcCon = Connection<RedisConnectionManager>;
// type Result<T> = std::result::Result<T, Error>;
//
// const CACHE_POOL_MAX_OPEN: u64 = 16;
// const CACHE_POOL_MAX_IDLE: u64 = 8;
// const CACHE_POOL_TIMEOUT_SECONDS: u64 = 1;
// const CACHE_POOL_EXPIRE_SECONDS: u64 = 60;
//
// #[derive(Error, Debug)]
// pub enum Error {
//     #[error("mobc error: {0}")]
//     MobcError(#[from] MobcError),
// }
//
// #[derive(Error, Debug)]
// pub enum MobcError {
//     #[error("could not get redis connection from pool : {0}")]
//     RedisPoolError(mobc::Error<redis::RedisError>),
//     #[error("error parsing string from redis result: {0}")]
//     RedisTypeError(redis::RedisError),
//     #[error("error executing redis command: {0}")]
//     RedisCMDError(redis::RedisError),
//     #[error("error creating Redis client: {0}")]
//     RedisClientError(redis::RedisError),
// }
//
// pub async fn connect(config: Config) -> Result<MobcPool> {
//     let client = redis::Client::open(config.redis_url).map_err(RedisClientError)?;
//     let manager = RedisConnectionManager::new(client);
//     Ok(Pool::builder()
//         .get_timeout(Some(Duration::from_secs(CACHE_POOL_TIMEOUT_SECONDS)))
//         .max_open(CACHE_POOL_MAX_OPEN)
//         .max_idle(CACHE_POOL_MAX_IDLE)
//         .max_lifetime(Some(Duration::from_secs(CACHE_POOL_EXPIRE_SECONDS)))
//         .build(manager))
// }
//
// async fn get_con(pool: &MobcPool) -> Result<MobcCon> {
//     pool.get().await.map_err(|e| {
//         eprintln!("error connecting to redis: {}", e);
//         RedisPoolError(e).into()
//     })
// }
//
// pub async fn set_str(pool: &MobcPool, key: &str, value: &str, ttl_seconds: usize) -> Result<()> {
//     let mut con = get_con(&pool).await?;
//     con.set(key, value).await.map_err(RedisCMDError)?;
//     if ttl_seconds > 0 {
//         con.expire(key, ttl_seconds).await.map_err(RedisCMDError)?;
//     }
//     Ok(())
// }
//
// pub async fn get_str(pool: &MobcPool, key: &str) -> Result<String> {
//     let mut con = get_con(&pool).await?;
//     let value = con.get(key).await.map_err(RedisCMDError)?;
//     FromRedisValue::from_redis_value(&value).map_err(|e| RedisTypeError(e).into())
// }

use crate::config::config::Config;
// use crate::repository::redis::Error::MobcError;
// use crate::repository::redis::MobcError::{RedisCMDError, RedisPoolError, RedisTypeError};
use log::error;
// use mobc::{Connection, Pool};
// use crate::repository::redis::DeadError::{RedisCMDError, RedisPoolError, RedisTypeError};
use crate::repository::redis::DeadpoolError::{RedisCMDError, RedisPoolError, RedisTypeError};
// use crate::repository::redis::DeapError::{RedisCMDError, RedisPoolError, RedisTypeError};
use deadpool_redis::{
    redis::{cmd, AsyncCommands},
    Config as RedisConfig, Connection, Pool, PoolError, Runtime,
};
// use mobc_redis::{
//     redis,
//     redis::{AsyncCommands, FromRedisValue},
//     RedisConnectionManager,
// };
use redis::FromRedisValue;
use std::time::Duration;
use thiserror::Error;

// pub type RedisPool = Pool<RedisConnectionManager>;
// pub type MobcConn = Connection<RedisConnectionManager>;
type Result<T> = std::result::Result<T, Error>;

pub struct Redis {
    pool: Pool,
}

const CACHE_POOL_MAX_OPEN: u64 = 16;
const CACHE_POOL_MAX_IDLE: u64 = 10;
const CACHE_POOL_TIMEOUT_SECONDS: u64 = 30;
const CACHE_POOL_EXPIRE_SECONDS: u64 = 60;

#[derive(Error, Debug)]
pub enum Error {
    #[error("deadpool error: {0}")]
    DeadpoolError(#[from] DeadpoolError),
}

#[derive(Error, Debug)]
pub enum DeadpoolError {
    #[error("could not get redis connection from pool : {0}")]
    RedisPoolError(PoolError),
    #[error("error parsing string from redis result: {0}")]
    RedisTypeError(redis::RedisError),
    #[error("error executing redis command: {0}")]
    RedisCMDError(redis::RedisError),
    #[error("error creating Redis client: {0}")]
    RedisClientError(redis::RedisError),
}

impl Redis {
    pub fn new(config: Config) -> Self {
        let redis_config = RedisConfig::from_url(config.redis_url);
        let pool = redis_config.create_pool(Some(Runtime::Tokio1)).unwrap();
        // let client = redis::Client::open(config.redis_url)
        //     .map_err(MobcError::RedisClientError)
        //     .expect("Failed to create open redis client");
        // let manager = RedisConnectionManager::new(client);
        // let pool = Pool::builder()
        //     .get_timeout(Some(Duration::from_secs(CACHE_POOL_TIMEOUT_SECONDS)))
        //     .max_open(CACHE_POOL_MAX_OPEN)
        //     .max_idle(CACHE_POOL_MAX_IDLE)
        //     .max_lifetime(Some(Duration::from_secs(CACHE_POOL_EXPIRE_SECONDS)))
        //     .build(manager);
        //
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
            // .set(key, value)
            .await
            .map_err(RedisCMDError)?;
        // if ttl_seconds > 0 {
        //     con.expire(key, ttl_seconds).await.map_err(RedisCMDError)?;
        // }
        Ok(())
    }

    pub async fn get_str(&self, key: &str) -> Result<String> {
        let mut conn = self.get_conn().await?;
        // let value = &con.get(key).await.map_err(RedisCMDError)?;
        Ok(cmd("GET")
            .arg(key)
            .query_async(&mut conn)
            .await
            .map_err(RedisCMDError)?)
        // FromRedisValue::from_redis_value(value).map_err(|e| RedisTypeError(e).into())
    }
}
