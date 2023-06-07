use crate::config::jwt_auth;
use crate::models::user::{LoginUserSchema, RegisterUserSchema};
use crate::repository::database::Database;
use crate::service::user::{create_user_service, login_user_service};
use actix_web::cookie::{time::Duration as ActixWebDuration, Cookie};
use actix_web::web::{Data, Json};
use actix_web::{post, web, HttpResponse, Responder};
use serde_json::json;

#[post("/auth/register")]
async fn register_user_handler(
    db: Data<Database>,
    new_user: Json<RegisterUserSchema>,
) -> impl Responder {
    create_user_service(db, new_user).await
}

#[post("/auth/login")]
async fn login_user_handler(
    db: Data<Database>,
    login_user: Json<LoginUserSchema>,
) -> impl Responder {
    login_user_service(db, login_user).await
}

#[post("/auth/logout")]
async fn logout_user_handler(_: jwt_auth::JwtMiddleware) -> impl Responder {
    let cookie = Cookie::build("token", "")
        .path("/")
        .max_age(ActixWebDuration::new(-1, 0))
        .http_only(true)
        .finish();

    HttpResponse::Ok().cookie(cookie).json(json!({
        "status": "success"
    }))
}

pub fn config(conf: &mut web::ServiceConfig) {
    let scope = web::scope("/api/v2")
        .service(register_user_handler)
        .service(login_user_handler)
        .service(logout_user_handler);

    conf.service(scope);
}
