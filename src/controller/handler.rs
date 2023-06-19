use crate::config::jwt_auth::JwtMiddleware;
use crate::model::user::{LoginUserSchema, RegisterUserSchema, VerifyEmailRequest};
use crate::service::user::{
    create_user_service, get_all_user_info_service, login_user_service, logout_user_service,
    refresh_auth_token_service, verify_email,
};
use crate::AppState;
use actix_web::web::{service, Data, Json};
use actix_web::{get, post, web, HttpRequest, Responder};

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
async fn logout_user_handler(
    req: HttpRequest,
    auth_guard: JwtMiddleware,
    data: Data<AppState>,
) -> impl Responder {
    logout_user_service(req, auth_guard, data).await
}

#[get("/users/me")]
async fn get_user_info_handler(auth: JwtMiddleware) -> impl Responder {
    get_all_user_info_service(auth).await
}

#[get("/auth/refresh")]
async fn refresh_auth_handler(req: HttpRequest, data: Data<AppState>) -> impl Responder {
    refresh_auth_token_service(req, data).await
}

#[post("/user/verify-email")]
async fn verify_email_handler(
    verify_email_req: Json<VerifyEmailRequest>,
    jwt_guard: JwtMiddleware,
    data: Data<AppState>,
) -> impl Responder {
    verify_email(verify_email_req, jwt_guard, data).await
}

pub fn config(conf: &mut web::ServiceConfig) {
    let scope = web::scope("/api/v2")
        .service(get_user_info_handler)
        .service(register_user_handler)
        .service(login_user_handler)
        .service(logout_user_handler)
        .service(refresh_auth_handler)
        .service(verify_email_handler);

    conf.service(scope);
}
