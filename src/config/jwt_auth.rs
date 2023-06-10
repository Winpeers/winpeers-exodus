use crate::models::user::User;
use crate::util::token;
use crate::AppState;
use actix_web::error::{ErrorInternalServerError, ErrorUnauthorized};
use actix_web::{dev::Payload, web, Error as ActixWebError};
use actix_web::{http, FromRequest, HttpRequest};
use futures::executor::block_on;
use serde::Serialize;
use std::fmt;
use std::fmt::Formatter;
use std::future::{ready, Ready};

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    status: String,
    message: String,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
    }
}

pub struct JwtMiddleware {
    pub user: User,
    pub access_token_uuid: uuid::Uuid,
}

impl FromRequest for JwtMiddleware {
    type Error = ActixWebError;
    type Future = Ready<Result<Self, Self::Error>>;
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let data = req.app_data::<web::Data<AppState>>().unwrap();

        let access_token = req
            .cookie("access_token")
            .map(|c| c.value().to_string())
            .or_else(|| {
                req.headers()
                    .get(http::header::AUTHORIZATION)
                    .map(|h| h.to_str().unwrap().split_at(7).1.to_string())
            });

        if access_token.is_none() {
            let json_error = ErrorResponse {
                status: "failed".to_string(),
                message: "You are not logged in, please provide token".to_string(),
            };
            return ready(Err(ErrorUnauthorized(json_error)));
        }

        let access_token_details = match token::verify_jwt_token(
            data.config.access_token_public_key.to_owned(),
            &access_token.unwrap(),
        ) {
            Ok(token_details) => token_details,
            Err(e) => {
                let json_error = ErrorResponse {
                    status: "failed".to_string(),
                    message: format!("{:?}", e),
                };
                return ready(Err(ErrorUnauthorized(json_error)));
            }
        };

        let access_token_uuid =
            uuid::Uuid::parse_str(&access_token_details.token_uuid.to_string()).unwrap();

        let user_email_redis_result = async move {
            let redis_result = data
                .redis_db
                .get_str(&access_token_uuid.clone().to_string())
                .await;

            match redis_result {
                Ok(val) => Ok(val),
                Err(_) => Err(ErrorUnauthorized(ErrorResponse {
                    status: "failed".to_string(),
                    message: "Token is invalid or session has expired".to_string(),
                })),
            }
        };

        let user_exists_result = async move {
            let user_email = user_email_redis_result.await?;
            match data.db.find_all_user_info(&user_email).await {
                Ok(Some(user)) => Ok(user),
                Ok(None) => {
                    let json_error = ErrorResponse {
                        status: "failed".to_string(),
                        message: "The user belonging to this token no logger exists".to_string(),
                    };
                    Err(ErrorUnauthorized(json_error))
                }
                Err(_) => {
                    let json_error = ErrorResponse {
                        status: "error".to_string(),
                        message: "Failed to check user existence".to_string(),
                    };
                    Err(ErrorInternalServerError(json_error))
                }
            }
        };

        match block_on(user_exists_result) {
            Ok(user) => ready(Ok(JwtMiddleware {
                user,
                access_token_uuid,
            })),
            Err(e) => ready(Err(e)),
        }
    }
}
