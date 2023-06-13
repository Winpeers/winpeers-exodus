use crate::config::config::Config;
use crate::repository::database::Database;
use crate::repository::redis::Redis;
use crate::util::real_ip_key_extractor::RealIpKeyExtractor;
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder, Result};
use serde::Serialize;
use std::net::IpAddr;
use std::str::FromStr;

mod config;
mod controller;
mod model;
mod repository;
mod service;
mod util;

#[derive(Serialize)]
pub struct Response {
    status: String,
    message: String,
}

#[get("/health")]
async fn health_check() -> impl Responder {
    let response = Response {
        status: "Success".to_string(),
        message: "Everything is working as expected".to_string(),
    };
    HttpResponse::Ok().json(response)
}

async fn not_found() -> Result<HttpResponse> {
    let response = Response {
        status: "Failed".to_string(),
        message: "Resource not found".to_string(),
    };
    Ok(HttpResponse::NotFound().json(response))
}

pub struct AppState {
    db: Database,
    redis_db: Redis,
    config: Config,
    trusted_reverse_proxy_ip: IpAddr,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let trusted_reverse_proxy_ip = IpAddr::from_str("127.0.0.1").unwrap();
    log4rs::init_file("./log-config.yml", Default::default()).expect("Log config file not found.");
    let config = Config::init();
    let db = Database::new(config.clone());
    let redis_db = Redis::new(config.clone());
    let app_data = web::Data::new(AppState {
        db,
        redis_db,
        config,
        trusted_reverse_proxy_ip,
    });

    let governor_conf = GovernorConfigBuilder::default()
        .per_second(10)
        .burst_size(5)
        .key_extractor(RealIpKeyExtractor)
        // .use_headers()
        .finish()
        .unwrap();

    HttpServer::new(move || {
        App::new()
            .app_data(app_data.clone())
            .configure(controller::handler::config)
            .service(health_check)
            .default_service(web::route().to(not_found))
            .wrap(actix_web::middleware::Logger::default())
            .wrap(Governor::new(&governor_conf))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
