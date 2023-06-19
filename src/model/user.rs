use diesel::backend::Backend;
use diesel::sql_types::Nullable;
use diesel::{AsChangeset, Insertable, Queryable};
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Serialize, Deserialize, Debug, Clone, Queryable, Insertable, AsChangeset, Default)]
#[diesel(table_name = crate::model::schema::users)]
pub struct User {
    #[serde(default)]
    pub uuid_id: String,
    pub email: String,
    pub username: String,
    pub phone: Option<String>,
    pub password: String,
    pub confirmed_email: Option<bool>,
    pub confirm_email_token: Option<i32>,
    pub confirmed_phone: Option<bool>,
    pub confirm_phone_token: Option<i32>,
    pub current_available_funds: i32,
    #[serde(rename = "createdAt")]
    pub created_at: Option<chrono::NaiveDateTime>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<chrono::NaiveDateTime>,
}

lazy_static! {
    static ref USER_NAME_RE: Regex = Regex::new(r"^[a-zA-Z0-9]{5,}$").unwrap();
    static ref PASSWORD_RE: Regex = Regex::new(r"^[A-Za-z\d@$!%*?&]{6,}$").unwrap();
    static ref PHONE_NUMBER_MATCH_RE: Regex = Regex::new(r"^\d{9,}$").unwrap();
    static ref TOKEN_MATCH_RE: Regex = Regex::new(r"^\d{6}$").unwrap();
}
#[derive(Debug, Deserialize, Queryable, Clone, Validate)]
pub struct RegisterUserSchema {
    #[validate(regex(
        path = "USER_NAME_RE",
        message = "Username can be alphanumeric and must be longer than 5 characters"
    ))]
    pub username: String,
    #[validate(email(message = "Must be a valid email"))]
    pub email: String,
    #[validate(regex(
        path = "PHONE_NUMBER_MATCH_RE",
        message = "Phone must be a number and must be longer than 9 characters"
    ))]
    pub phone: Option<String>,
    #[validate(regex(
        path = "PASSWORD_RE",
        message = "Password must be between 6 and 25 characters long. \
        It can only contain letters, numbers and the following special characters (@, $, !, %, *, ?, &)"
    ))]
    pub password: String,
}

#[derive(Debug, Deserialize, Queryable, Validate)]
pub struct LoginUserSchema {
    #[validate(regex(
        path = "USER_NAME_RE",
        message = "Username can be alphanumeric and must be longer than 5 characters"
    ))]
    pub username: Option<String>,
    #[validate(email(message = "Must be a valid email"))]
    pub email: Option<String>,
    #[validate(regex(
        path = "PHONE_NUMBER_MATCH_RE",
        message = "Phone must be a number and must be longer than 9 characters"
    ))]
    pub phone: Option<String>,
    #[validate(regex(
        path = "PASSWORD_RE",
        message = "Password must be between 6 and 25 characters long. \
        It can only contain letters, numbers and the following special characters (@, $, !, %, *, ?, &)"
    ))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct VerifyEmailRequest {
    #[validate(regex(
        path = "TOKEN_MATCH_RE",
        message = "token must be a number and must be 6 characters long"
    ))]
    pub token: String,
}

#[derive(Queryable)]
#[diesel(table_name = crate::model::schema::users)]
pub struct ConfirmEmailToken {
    pub uuid_id: String,
    pub confirm_email_token: Option<i32>,
}
