use diesel::{AsChangeset, Insertable, Queryable};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = crate::models::schema::users)]
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

#[derive(Debug, Deserialize, Queryable)]
pub struct RegisterUserSchema {
    pub username: String,
    pub email: String,
    pub phone: Option<String>,
    pub password: String,
}

#[derive(Debug, Deserialize, Queryable)]
pub struct LoginUserSchema {
    pub username: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub password: String,
}
