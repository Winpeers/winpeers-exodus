use crate::model::user::User;
use crate::util::token;
use crate::AppState;
use actix_web::{dev::Payload, web, HttpResponse, ResponseError};
use actix_web::{http, FromRequest, HttpRequest};
use log::error;
use serde::Serialize;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::future::ready;
use std::pin::Pin;

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    status: String,
    message: String,
}

#[derive(Debug, Serialize)]
pub struct AuthError(pub ErrorResponse);

impl Display for ErrorResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
    }
}

impl Display for AuthError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(&self.0).unwrap())
    }
}

impl ResponseError for AuthError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::Unauthorized().json(self)
    }
}

impl From<actix_web::Error> for AuthError {
    fn from(error: actix_web::Error) -> Self {
        AuthError(ErrorResponse {
            status: "failed".to_string(),
            message: format!("An Error occurred: {}", error),
        })
    }
}

pub struct JwtMiddleware {
    pub user: User,
    pub access_token_uuid: uuid::Uuid,
}

impl FromRequest for JwtMiddleware {
    type Error = AuthError;
    type Future = Pin<Box<dyn futures::Future<Output = Result<Self, Self::Error>>>>;
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let datax = req.app_data::<web::Data<AppState>>().unwrap();
        let data = datax.clone();

        let access_token = if let Some(cookie) = req.cookie("access_token") {
            Some(cookie.value().to_string())
        } else {
            req.headers()
                .get(http::header::AUTHORIZATION)
                .and_then(|header| header.to_str().ok())
                .filter(|header| !header.is_empty())
                .and_then(|header| {
                    if header.starts_with("Bearer ") {
                        Some(header[7..].to_string())
                    } else {
                        None
                    }
                })
        };

        if access_token.is_none() {
            let json_error = AuthError(ErrorResponse {
                status: "failed".to_string(),
                message: "You are not logged in, please provide token".to_string(),
            });
            return Box::pin(ready(Err(json_error)));
        }

        let access_token_details = match token::verify_jwt_token(
            data.config.access_token_public_key.to_owned(),
            &access_token.unwrap(),
        ) {
            Ok(token_details) => token_details,
            Err(e) => {
                error!("An error occurred. The error: {:?}", e);
                let json_error = AuthError(ErrorResponse {
                    status: "failed".to_string(),
                    message: "The token has expired".to_string(),
                });
                return Box::pin(ready(Err(json_error)));
            }
        };

        let access_token_uuid =
            uuid::Uuid::parse_str(&access_token_details.token_uuid.to_string()).unwrap();

        Box::pin(async move {
            let redis_result = data
                .redis_db
                .get_str(&access_token_uuid.clone().to_string())
                .await;

            let user_email = match redis_result {
                Ok(val) => val,
                Err(e) => {
                    error!("The error: {:?}", e);
                    return Err(AuthError(ErrorResponse {
                        status: "failed".to_string(),
                        message: "Token is invalid or session has expired".to_string(),
                    }));
                }
            };

            let user = match data.db.find_all_user_info(&user_email).await {
                Ok(Some(user)) => user,
                Ok(None) => {
                    let json_error = AuthError(ErrorResponse {
                        status: "failed".to_string(),
                        message: "The user belonging to this token no logger exists".to_string(),
                    });
                    return Err(json_error);
                }
                Err(_) => {
                    let json_error = AuthError(ErrorResponse {
                        status: "error".to_string(),
                        message: "Failed to check user existence".to_string(),
                    });
                    return Err(json_error);
                }
            };

            Ok(JwtMiddleware {
                user,
                access_token_uuid,
            })
        })
    }
}
