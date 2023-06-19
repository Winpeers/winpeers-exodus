use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct FilteredUser {
    pub uuid: String,
    pub email: String,
    pub username: String,
    pub phone: Option<String>,
    #[serde(rename = "confirmedEmail")]
    pub confirmed_email: Option<bool>,
    #[serde(rename = "confirmedEmailToken")]
    pub confirmed_email_token: Option<i32>,
    #[serde(rename = "confirmedPhone")]
    pub confirmed_phone: Option<bool>,
    #[serde(rename = "currentAvailableFunds")]
    pub current_available_funds: i32,
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
