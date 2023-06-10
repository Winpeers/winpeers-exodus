use crate::config::config::Config;
use crate::repository::database::Database;
use crate::repository::redis::Redis;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder, Result};
use serde::Serialize;

mod api;
mod config;
mod models;
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
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    log4rs::init_file("./log-config.yml", Default::default()).expect("Log config file not found.");
    let config = Config::init();
    let db = Database::new(config.clone());
    let redis_db = Redis::new(config.clone());
    let app_data = web::Data::new(AppState {
        db,
        redis_db,
        config,
    });

    HttpServer::new(move || {
        App::new()
            .app_data(app_data.clone())
            .configure(api::handler::config)
            .service(health_check)
            .default_service(web::route().to(not_found))
            .wrap(actix_web::middleware::Logger::default())
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
