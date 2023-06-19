use crate::config::jwt_auth::JwtMiddleware;
use crate::model::schema::users::{confirm_email_token, confirmed_phone};
use crate::model::user::{LoginUserSchema, VerifyEmailRequest};
use crate::model::{
    response::FilteredUser,
    user::{RegisterUserSchema, User},
};
use crate::repository::database::{AuthenticationError, ResponseData};
use crate::util::random_num_gen::generate_random_number;
use crate::util::send_email::{send_email_verify_mail, send_welcome_email};
use crate::util::token::{generate_jwt_token, verify_jwt_token};
use crate::AppState;
use actix_web::{
    cookie::{time::Duration as ActixWebDuration, Cookie},
    http,
    web::{Data, Json},
    HttpRequest, HttpResponse, Responder,
};
use futures::future::err;
use log::error;
use serde_json::json;
use validator::Validate;

fn filter_user_record(user: &User) -> FilteredUser {
    FilteredUser {
        uuid: user.uuid_id.to_string(),
        email: user.email.to_owned(),
        username: user.username.to_owned(),
        phone: user.phone.to_owned(),
        confirmed_email: user.confirmed_email,
        confirmed_email_token: user.confirm_email_token,
        confirmed_phone: user.confirmed_phone,
        current_available_funds: user.current_available_funds.to_owned(),
        created_at: Some(user.created_at.unwrap()),
        updated_at: Some(user.updated_at.unwrap()),
    }
}

pub async fn create_user_service(
    data_b: Data<AppState>,
    new_user: Json<RegisterUserSchema>,
) -> impl Responder {
    let is_valid = new_user.validate();
    match is_valid {
        Ok(_) => {
            let user_data = match data_b.db.create_user(new_user.into_inner()).await {
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
                "Data Exists" => HttpResponse::Conflict().json(json!({
                    "status": "failed",
                    "message": "User with that username/email/phone already exists"
                })),
                "Data Inserted" => match &res_data.user {
                    Some(data) => {
                        let random_number = generate_random_number().await;
                        match data_b
                            .db
                            .update_email_verification_things(data.to_owned(), random_number, false)
                            .await
                        {
                            Ok(user) => {
                                let user_info = &user.unwrap_or_else(|| User {
                                    ..Default::default()
                                });
                                match send_email_verify_mail(
                                    &user_info.username,
                                    &user_info.email,
                                    random_number,
                                )
                                .await
                                {
                                    Ok(_) => {}
                                    Err(_err) => {}
                                }

                                let user_response = json!({
                                    "status": "success",
                                    "data": {
                                        "user": filter_user_record(user_info),
                                    }
                                });

                                HttpResponse::Ok().json(user_response)
                            }
                            Err(e) => {
                                error!("An error occurred in create_user -> verify_email service. The error: {:?}", e);
                                HttpResponse::BadRequest().json(json!({
                                    "status": "failed",
                                    "message": "An error occurred"
                                }))
                            }
                        }
                    }
                    None => HttpResponse::InternalServerError()
                        .json(json!({"status": "failed","message": "An error occurred"})),
                },
                "User Failed to be Inserted" => HttpResponse::InternalServerError().json(json!({
                    "status": "failed",
                    "message": "An error occurred"
                })),
                _ => HttpResponse::InternalServerError().finish(),
            }
        }
        Err(err) => HttpResponse::BadRequest().json(err),
    }
}

pub async fn login_user_service(
    login_user: Json<LoginUserSchema>,
    data: Data<AppState>,
) -> impl Responder {
    let is_valid = login_user.validate();
    match is_valid {
        Ok(_) => match data.db.verify_user_password(login_user.into_inner()).await {
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
                            return HttpResponse::BadGateway().json(
                                json!({"status": "failed", "message": "An error has occurred"}),
                            );
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
                        return HttpResponse::UnprocessableEntity()
                            .json(json!({"status": "error", "message": format_args!("{}", e)}));
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
                        return HttpResponse::UnprocessableEntity()
                            .json(json!({"status": "error", "message": format_args!("{}", e)}));
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
                    let refresh_cookie = Cookie::build(
                        "refresh_token",
                        refresh_token_details.token.clone().unwrap(),
                    )
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
                        .json(json!({
                        "status": "success", "access_token": access_token_details.token.unwrap(), 
                        "refresh_token": refresh_token_details.token.unwrap(), 
                        "expires_in": data.config.access_token_max_age * 60}))
                }
                None => HttpResponse::BadRequest().json(json!({
                    "status": "failed",
                    "message": "Invalid email or password or phone"
                })),
            },
            Ok(None) => HttpResponse::BadRequest().json(json!({
                "status": "failed",
                "message": "Invalid email or password or phone"
            })),
            Err(auth_error) => {
                error!(
                    "An error occurred in the login_user_service function. The error: {:?}",
                    auth_error
                );
                HttpResponse::BadRequest().json(json!({
                    "status": "failed",
                    "message": "Incorrect email or password or phone"
                }))
            }
        },
        Err(err) => HttpResponse::BadRequest().json(err),
    }
}

pub async fn get_all_user_info_service(jwt_guard: JwtMiddleware) -> impl Responder {
    if let Some(false) = jwt_guard.user.confirmed_email {
        HttpResponse::ExpectationFailed().json(json!({
            "status": "failed",
            "message": "Verify you email address"
        }))
    } else {
        let json_response = json!({
            "status":  "success",
            "data": serde_json::json!({
                "user": filter_user_record(&jwt_guard.user)
            })
        });

        HttpResponse::Ok().json(json_response)
    }
}

pub async fn refresh_auth_token_service(req: HttpRequest, data: Data<AppState>) -> impl Responder {
    let message = "Could not refresh access token. Login again.";

    let refresh_token = if let Some(cookie) = req.cookie("refresh_token") {
        Some(cookie.value().to_string())
    } else {
        req.headers()
            .get(http::header::HeaderName::from_static(
                "x-winp-refresh-token",
            ))
            .and_then(|header| header.to_str().ok())
            .filter(|header_value| !header_value.is_empty())
            .and_then(|header_value| {
                if header_value.starts_with("Winpeers ") {
                    Some(
                        header_value
                            .strip_prefix("Winpeers ")
                            .unwrap_or("")
                            .to_string(),
                    )
                } else {
                    None
                }
            })
    };

    if refresh_token.is_none() {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"status": "failed", "message": message}));
    }

    let refresh_token_details = match verify_jwt_token(
        data.config.refresh_token_public_key.to_owned(),
        &refresh_token.unwrap(),
    ) {
        Ok(token_details) => token_details,
        Err(e) => {
            error!("An error occurred. The error: {:?}", e);
            return HttpResponse::Forbidden().json(
                serde_json::json!({"status": "failed", "message": "The refresh token has expired"}),
            );
        }
    };

    let user_email = match data
        .redis_db
        .get_str(&refresh_token_details.token_uuid.to_string())
        .await
    {
        Ok(val) => val,
        Err(_) => {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "status": "failed",
                "message": message
            }))
        }
    };

    let user = match data.db.find_all_user_info(&user_email).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "status":"failed",
                "message": message
            }));
        }
        Err(_) => {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "status":"failed",
                "message": message
            }));
        }
    };

    let access_token_details = match generate_jwt_token(
        user.email.clone(),
        data.config.access_token_max_age,
        data.config.access_token_private_key.to_string(),
    ) {
        Ok(token_details) => token_details,
        Err(e) => {
            error!("An error occurred. The error: {:?}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "status": "failed",
                "message": "An error occurred. Access token generation failed"
            }));
        }
    };

    let access_result = data
        .redis_db
        .set_str(
            &access_token_details.token_uuid.to_string(),
            &user.email,
            (data.config.access_token_max_age * 60) as usize,
        )
        .await;
    if let Err(e) = access_result {
        return HttpResponse::UnprocessableEntity()
            .json(json!({"status": "error", "message": format_args!("{}", e)}));
    }

    let access_cookie = Cookie::build("access_token", access_token_details.token.clone().unwrap())
        .path("/")
        .max_age(ActixWebDuration::new(
            (data.config.access_token_max_age * 60) as i64,
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
        .cookie(logged_in_cookie)
        .json(json!({"status": "success", "access_token": access_token_details.token.unwrap()}))
}

pub async fn logout_user_service(
    req: HttpRequest,
    auth_guard: JwtMiddleware,
    data: Data<AppState>,
) -> impl Responder {
    let refresh_token = if let Some(cookie) = req.cookie("refresh_token") {
        Some(cookie.value().to_string())
    } else {
        req.headers()
            .get(http::header::HeaderName::from_static(
                "x-winp-refresh-token",
            ))
            .and_then(|header| header.to_str().ok())
            .filter(|header_value| !header_value.is_empty())
            .and_then(|header_value| {
                if header_value.starts_with("Winpeers ") {
                    Some(
                        header_value
                            .strip_prefix("Winpeers ")
                            .unwrap_or("")
                            .to_string(),
                    )
                } else {
                    None
                }
            })
    };

    if refresh_token.is_none() {
        return HttpResponse::Unauthorized()
            .json(json!({"status": "failed", "message": "Refresh token header does not exist", "action": "RE_LOGIN"}));
    }

    let refresh_token_details = match verify_jwt_token(
        data.config.refresh_token_public_key.to_owned(),
        &refresh_token.unwrap(),
    ) {
        Ok(token_details) => token_details,
        Err(e) => {
            error!("An error occurred. The error: {:?}", e);
            return HttpResponse::Unauthorized().json(
                json!({"status": "failed", "message": "The refresh token has expired", "action": "RE_LOGIN"}),
            );
        }
    };

    match data
        .redis_db
        .delete_key(
            &auth_guard.access_token_uuid.to_string(),
            &refresh_token_details.token_uuid.to_string(),
        )
        .await
    {
        Ok(_) => {
            let access_cookie = Cookie::build("access_token", "")
                .path("/")
                .max_age(ActixWebDuration::new(-1, 0))
                .http_only(true)
                .finish();
            let refresh_cookie = Cookie::build("refresh_token", "")
                .path("/")
                .max_age(ActixWebDuration::new(-1, 0))
                .http_only(true)
                .finish();
            let logged_in_cookie = Cookie::build("logged_in", "")
                .path("/")
                .max_age(ActixWebDuration::new(-1, 0))
                .http_only(true)
                .finish();

            HttpResponse::Ok()
                .cookie(access_cookie)
                .cookie(refresh_cookie)
                .cookie(logged_in_cookie)
                .json(json!({
                    "status": "success",
                    "message": "Logged out successfully"
                }))
        }
        Err(e) => {
            error!("An error occurred. The error: {:?}", e);
            HttpResponse::BadGateway().json(json!({
                "status": "failed",
                "message": "Graceful Logout failed"
            }))
        }
    }
}

pub async fn verify_email(
    verify_email_req: Json<VerifyEmailRequest>,
    jwt_guard: JwtMiddleware,
    data: Data<AppState>,
) -> impl Responder {
    let is_valid = verify_email_req.validate();
    match is_valid {
        Ok(_) => {
            if let Some(false) = jwt_guard.user.confirmed_email {
                let tok = verify_email_req.into_inner().token;
                let user = jwt_guard.user;
                if user
                    .confirm_email_token
                    .eq(&Some(tok.as_str().parse::<i32>().unwrap()))
                {
                    match data
                        .db
                        .update_email_verification_things(user, 0, true)
                        .await
                    {
                        Ok(user) => {
                            let user_info = &user.unwrap_or_else(|| User {
                                ..Default::default()
                            });
                            match send_welcome_email(&user_info.username, &user_info.email).await {
                                Ok(_) => {}
                                Err(_err) => {}
                            }

                            HttpResponse::Ok().json(json!({
                                "status": "success",
                                "message": "Email verified successfully"
                            }))
                        }
                        Err(e) => {
                            error!("An error occurred. The error: {:?}", e);
                            HttpResponse::BadRequest().json(json!({
                                "status": "failed",
                                "message": "Email verification failed"
                            }))
                        }
                    }
                } else {
                    HttpResponse::Forbidden().finish()
                }
            } else {
                HttpResponse::Forbidden().finish()
            }
        }
        Err(err) => HttpResponse::BadRequest().json(err),
    }
}
