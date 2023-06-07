use crate::config::config::Config;
use crate::models::user::LoginUserSchema;
use crate::models::{
    response::FilteredUser,
    token_claims::TokenClaims,
    user::{RegisterUserSchema, User},
};
use crate::repository::database::Database;
use actix_web::{
    cookie::{time::Duration as ActixWebDuration, Cookie},
    web::{Data, Json},
    HttpResponse, Responder,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use log::error;
use serde_json::json;

fn filter_user_record(user: &User) -> FilteredUser {
    FilteredUser {
        uuid: user.uuid.to_string(),
        email: user.email.to_owned(),
        username: user.username.to_owned(),
        phone: user.phone.to_owned(),
        confirmed_email: user.confirmed_email,
        confirmed_phone: user.confirmed_phone,
        current_available_funds: user.current_available_funds.to_owned(),
        created_at: Some(user.created_at.unwrap()),
        updated_at: Some(user.updated_at.unwrap()),
    }
}

pub async fn create_user_service(
    db: Data<Database>,
    new_user: Json<RegisterUserSchema>,
) -> impl Responder {
    let user_data = db.create_user(new_user.into_inner()).await;
    match user_data.message.as_str() {
        "Data Exists" => HttpResponse::Conflict().json(serde_json::json!({
            "status": "failed",
            "message": "User with that username/email/phone already exists"
        })),
        "Data Inserted" => match &user_data.user {
            Some(data) => {
                let user_response = serde_json::json!({
                    "status": "success",
                    "data": {
                        "user": filter_user_record(data)
                    }
                });
                HttpResponse::Ok().json(user_response)
            }
            None => HttpResponse::InternalServerError()
                .json(serde_json::json!({"status": "failed","message": "An error occurred"})),
        },
        "User Failed to be Inserted" => {
            HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "failed",
                "message": "An error occurred"
            }))
        }
        _ => HttpResponse::InternalServerError().finish(),
    }
}

pub async fn login_user_service(
    db: Data<Database>,
    login_user: Json<LoginUserSchema>,
) -> impl Responder {
    let config = Config::init();
    match db.verify_user_password(login_user.into_inner()).await {
        Ok(Some(response_data)) => match response_data.data {
            Some(data_schemas) => {
                let now = Utc::now();
                let iat = now.timestamp() as usize;
                let exp = (now + Duration::minutes(60)).timestamp() as usize;
                let claims = TokenClaims {
                    sub: data_schemas.email,
                    iat,
                    exp,
                };

                let token = encode(
                    &Header::default(),
                    &claims,
                    &EncodingKey::from_secret(config.jwt_secret.as_ref()),
                )
                .unwrap();

                let cookie = Cookie::build("token", token.to_owned())
                    .path("/")
                    .max_age(ActixWebDuration::new(60 * 60, 0))
                    .http_only(true)
                    .finish();

                HttpResponse::Ok().cookie(cookie).json(json!({
                    "status": "success",
                    "token": token,
                    "exp": exp,
                }))
            }
            None => HttpResponse::BadRequest().json(serde_json::json!({
                "status": "failed",
                "message": "Invalid email or password or phone"
            })),
        },
        Ok(None) => HttpResponse::BadRequest().json(serde_json::json!({
            "status": "failed",
            "message": "Invalid email or password or phone"
        })),
        Err(auth_error) => {
            error!(
                "An error occurred in the login_user_service function. The error: {:?}",
                auth_error
            );
            HttpResponse::BadRequest().json(serde_json::json!({
                "status": "failed",
                "message": "Incorrect email or password or phone"
            }))
        }
    }
}
