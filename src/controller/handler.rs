use crate::config::jwt_auth;
use crate::model::user::{LoginUserSchema, RegisterUserSchema};
use crate::service::user::{
    create_user_service, get_all_user_info_service, login_user_service, refresh_auth_token_service,
};
use crate::AppState;
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::cookie::{time::Duration as ActixWebDuration, Cookie};
use actix_web::web::{service, Data, Json};
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use serde_json::json;

#[post("/auth/register")]
async fn register_user_handler(
    data: Data<AppState>,
    new_user: Json<RegisterUserSchema>,
) -> impl Responder {
    create_user_service(data, new_user).await
}

#[post("/auth/login")]
async fn login_user_handler(
    data: Data<AppState>,
    login_user: Json<LoginUserSchema>,
) -> impl Responder {
    login_user_service(login_user, data).await
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

#[get("/users/me")]
async fn get_user_info_handler(auth: jwt_auth::JwtMiddleware) -> impl Responder {
    get_all_user_info_service(auth).await
}

#[get("/auth/refresh")]
async fn refresh_auth_handler(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    refresh_auth_token_service(req, data).await
}

pub fn config(conf: &mut web::ServiceConfig) {
    let scope = web::scope("/api/v2")
        .service(get_user_info_handler)
        .service(register_user_handler)
        .service(login_user_handler)
        .service(logout_user_handler)
        .service(refresh_auth_handler);

    conf.service(scope);
}
