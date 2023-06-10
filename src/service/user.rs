use crate::config::config::Config;
use crate::config::jwt_auth;
use crate::models::user::LoginUserSchema;
use crate::models::{
    response::FilteredUser,
    token_claims::TokenClaims,
    user::{RegisterUserSchema, User},
};
use crate::repository::database::{AuthenticationError, Database, ResponseData};
use crate::util::token::generate_jwt_token;
use crate::AppState;
use actix_web::{
    cookie::{time::Duration as ActixWebDuration, Cookie},
    web,
    web::{Data, Json},
    HttpMessage, HttpRequest, HttpResponse, Responder,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use log::error;
use serde_json::json;

fn filter_user_record(user: &User) -> FilteredUser {
    FilteredUser {
        uuid: user.uuid_id.to_string(),
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
    data: Data<AppState>,
    new_user: Json<RegisterUserSchema>,
) -> impl Responder {
    let user_data = match data.db.create_user(new_user.into_inner()).await {
        Ok(response_data) => response_data,
        Err(err) => {
            error!("Returned no user information. Which would mean an issue occurred in creating the user. \
            I am never meant to see this error though as the issue that would cause this error should \
            already be handled upstream. The error is: {:?}", err);
            Some(ResponseData {
                message: "".to_string(),
                user: None,
                data: None,
            })
        }
    };
    let res_data = user_data.unwrap_or_else(|| ResponseData {
        message: "".to_string(),
        user: None,
        data: None,
    });
    match res_data.message.as_str() {
        "Data Exists" => HttpResponse::Conflict().json(serde_json::json!({
            "status": "failed",
            "message": "User with that username/email/phone already exists"
        })),
        "Data Inserted" => match &res_data.user {
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
    login_user: Json<LoginUserSchema>,
    data: Data<AppState>,
) -> impl Responder {
    match data.db.verify_user_password(login_user.into_inner()).await {
        Ok(Some(response_data)) => match response_data.data {
            Some(data_schemas) => {
                let access_token_details = match generate_jwt_token(
                    data_schemas.email.clone(),
                    data.config.access_token_max_age,
                    data.config.access_token_private_key.to_owned(),
                ) {
                    Ok(token_details) => token_details,
                    Err(e) => {
                        error!("An error has occurred. Error: {:?}", e);
                        return HttpResponse::BadGateway()
                            .json(serde_json::json!({"status": "failed", "message": "An error has occurred"}));
                    }
                };

                let refresh_token_details = match generate_jwt_token(
                    data_schemas.email.clone(),
                    data.config.refresh_token_max_age,
                    data.config.refresh_token_private_key.to_owned(),
                ) {
                    Ok(token_details) => token_details,
                    Err(e) => {
                        error!("An error has occurred. Error: {:?}", e);
                        return HttpResponse::BadGateway()
                            .json(serde_json::json!({"status": "failed", "message": "An error has occurred"}));
                    }
                };

                let access_result = data
                    .redis_db
                    .set_str(
                        &access_token_details.token_uuid.to_string(),
                        &data_schemas.email.clone(),
                        (data.config.access_token_max_age * 60) as usize,
                    )
                    .await;
                if let Err(e) = access_result {
                    return HttpResponse::UnprocessableEntity().json(
                        serde_json::json!({"status": "error", "message": format_args!("{}", e)}),
                    );
                }

                let refresh_result = data
                    .redis_db
                    .set_str(
                        &refresh_token_details.token_uuid.to_string(),
                        &data_schemas.email.clone(),
                        (data.config.refresh_token_max_age * 60) as usize,
                    )
                    .await;

                if let Err(e) = refresh_result {
                    return HttpResponse::UnprocessableEntity().json(
                        serde_json::json!({"status": "error", "message": format_args!("{}", e)}),
                    );
                }

                let access_cookie =
                    Cookie::build("access_token", access_token_details.token.clone().unwrap())
                        .path("/")
                        .max_age(ActixWebDuration::new(
                            (data.config.access_token_max_age * 60) as i64,
                            0,
                        ))
                        .http_only(true)
                        .finish();
                let refresh_cookie =
                    Cookie::build("refresh_token", refresh_token_details.token.unwrap())
                        .path("/")
                        .max_age(ActixWebDuration::new(
                            (data.config.refresh_token_max_age * 60) as i64,
                            0,
                        ))
                        .http_only(true)
                        .finish();
                let logged_in_cookie = Cookie::build("logged_in", "true")
                    .path("/")
                    .max_age(ActixWebDuration::new(
                        (data.config.access_token_max_age * 60) as i64,
                        0,
                    ))
                    .http_only(false)
                    .finish();

                HttpResponse::Ok()
                    .cookie(access_cookie)
                    .cookie(refresh_cookie)
                    .cookie(logged_in_cookie)
                    .json(serde_json::json!({"status": "success", "access_token": access_token_details.token.unwrap()}))

                // let now = Utc::now();
                // let iat = now.timestamp() as usize;
                // let exp = (now + Duration::minutes(1)).timestamp() as usize;
                // let claims = TokenClaims {
                //     sub: data_schemas.email,
                //     iat,
                //     exp,
                // };
                //
                // let token = encode(
                //     &Header::default(),
                //     &claims,
                //     &EncodingKey::from_secret(&data.config.jwt_secret.as_ref()),
                // )
                // .unwrap();
                //
                // let cookie = Cookie::build("token", token.to_owned())
                //     .path("/")
                //     .max_age(ActixWebDuration::new(60, 0))
                //     .http_only(true)
                //     .finish();
                //
                // HttpResponse::Ok().cookie(cookie).json(json!({
                //     "status": "success",
                //     "token": token,
                //     "exp": exp,
                // }))
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

pub async fn get_all_user_info_service(
    data: Data<AppState>,
    req: HttpRequest,
    _: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let user_email = if let Some(user_email) = req.extensions().get::<String>() {
        user_email.clone()
    } else {
        return HttpResponse::BadRequest().finish();
    };

    match data.db.find_all_user_info(&user_email).await {
        Ok(Some(data)) => {
            let response = serde_json::json!({
               "status": "success",
                "data": serde_json::json!({
                    "user": filter_user_record(&data)
                })
            });
            HttpResponse::Ok().json(response)
        }
        Err(auth_error) => {
            error!(
                "An error occurred in the login_user_service function. The error: {:?}",
                auth_error
            );
            HttpResponse::Unauthorized().finish()
        }
        _ => HttpResponse::Unauthorized().finish(),
    }
}
