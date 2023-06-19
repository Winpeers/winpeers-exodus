use diesel::Queryable;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct FilteredUser {
    pub uuid: String,
    pub email: String,
    pub username: String,
    pub phone: Option<String>,
    #[serde(rename = "confirmedEmail")]
    pub confirmed_email: Option<bool>,
    #[serde(rename = "confirmedPhone")]
    pub confirmed_phone: Option<bool>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<chrono::NaiveDateTime>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<chrono::NaiveDateTime>,
}

#[derive(Debug, Serialize)]
pub struct UserData {
    pub user: FilteredUser,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub status: String,
    pub data: UserData,
}

#[derive(Queryable, Default)]
#[diesel(table_name = crate::models::schema::users)]
pub struct ConfirmEmailResponse {
    pub uuid_id: String,
    pub email: String,
    pub username: String,
    pub reset_password_tokenizer: Option<String>,
}
