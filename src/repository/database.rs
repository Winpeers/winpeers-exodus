use crate::config::config::Config;
use crate::model::user::{ConfirmEmailToken, LoginUserSchema};
use crate::model::{
    schema::users::dsl::*,
    user::{RegisterUserSchema, User},
};
use crate::repository::database::AuthenticationError::{IncorrectPassword, UserDoesNotExist};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::Utc;
use deadpool::managed::Object;
use diesel::{BoolExpressionMethods, ExpressionMethods, OptionalExtension, QueryDsl, Table};
use diesel_async::{
    pooled_connection::{deadpool::Pool, AsyncDieselConnectionManager},
    AsyncPgConnection, RunQueryDsl,
};
use log::error;
use rand_core::OsRng;

pub type DBPool = deadpool::managed::Pool<AsyncDieselConnectionManager<AsyncPgConnection>>;

pub struct Database {
    pool: DBPool,
}

pub struct ResponseData {
    pub message: String,
    pub user: Option<User>,
    pub data: Option<RegisterUserSchema>,
}

#[derive(Debug)]
pub enum AuthenticationError {
    DBConnectionError,
    IncorrectPassword,
    UserDoesNotExist,
    Argon2Error(argon2::password_hash::Error),
    DatabaseError(diesel::result::Error),
    AsyncDatabaseError(diesel_async::pooled_connection::deadpool::PoolError),
}

impl From<argon2::password_hash::Error> for AuthenticationError {
    fn from(err: argon2::password_hash::Error) -> Self {
        AuthenticationError::Argon2Error(err)
    }
}

impl Database {
    pub fn new(config: Config) -> Self {
        let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(config.database_url);
        let pool = Pool::builder(manager)
            .build()
            .expect("Failed to create pool.");
        Database { pool }
    }

    // pub async fn find_user_confirm_email_token(
    //     &self,
    //     user_email: &str,
    // ) -> Result<Option<ConfirmEmailToken>, AuthenticationError> {
    //     let mut conn = self.get_db_conn().await?;
    //     let data = users
    //         .filter(email.eq(user_email))
    //         .select((uuid_id, confirm_email_token))
    //         .first::<ConfirmEmailToken>(&mut conn)
    //         .await
    //         .optional()
    //         .map_err(AuthenticationError::DatabaseError)?;
    //
    //     if let Some(confirm_token) = data {
    //         Ok(Some(confirm_token))
    //     } else {
    //         Ok(None)
    //     }
    // }

    pub async fn find_all_user_info(
        &self,
        user_email: &str,
    ) -> Result<Option<User>, AuthenticationError> {
        let mut conn = self.get_db_conn().await?;
        let data = users
            .filter(email.eq(user_email))
            .select((
                uuid_id,
                email,
                username,
                phone,
                password,
                confirmed_email,
                confirm_email_token,
                confirmed_phone,
                confirm_phone_token,
                current_available_funds,
                created_at,
                updated_at,
            ))
            .first::<User>(&mut conn)
            .await
            .optional()
            .map_err(AuthenticationError::DatabaseError)?;

        if let Some(user) = data {
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    async fn find_user_by_username_or_email_or_phone(
        &self,
        user_name: &str,
        user_email: &str,
        user_phone: &str,
    ) -> Result<Option<RegisterUserSchema>, AuthenticationError> {
        let mut conn = self.get_db_conn().await?;
        let exists = users
            .filter(
                username
                    .eq(user_name)
                    .or(email.eq(user_email))
                    .or(phone.eq(user_phone)),
            )
            .select((username, email, phone, password))
            .first::<RegisterUserSchema>(&mut conn)
            .await
            .optional()
            .map_err(AuthenticationError::DatabaseError)?;

        if let Some(user_data) = exists {
            Ok(Some(user_data))
        } else {
            Ok(None)
        }
    }

    pub async fn create_user(
        &self,
        req_body: RegisterUserSchema,
    ) -> Result<Option<ResponseData>, AuthenticationError> {
        //check if user already exist
        let user_phone = match req_body.phone {
            Some(user_phone) => user_phone,
            _ => "".to_owned(),
        };
        let user_exists = self
            .find_user_by_username_or_email_or_phone(
                &req_body.username,
                &req_body.email,
                &user_phone,
            )
            .await;

        let mut conn = self.get_db_conn().await?;
        match user_exists {
            Ok(Some(_)) => Ok(Some(ResponseData {
                message: "Data Exists".to_string(),
                user: None,
                data: None,
            })),
            Ok(None) => {
                let salt = SaltString::generate(&mut OsRng);
                let hashed_password = Argon2::default()
                    .hash_password(req_body.password.as_bytes(), &salt)
                    .expect("Error while hashing password")
                    .to_string();

                let user = User {
                    uuid_id: uuid::Uuid::new_v4().to_string(),
                    email: req_body.email.to_string(),
                    username: req_body.username.to_string(),
                    phone: Some(user_phone),
                    password: hashed_password,
                    current_available_funds: 0,
                    created_at: Some(Utc::now().naive_utc()),
                    updated_at: Some(Utc::now().naive_utc()),
                    ..Default::default()
                };

                match diesel::insert_into(users)
                    .values(&user)
                    .execute(&mut conn)
                    .await
                {
                    Ok(_) => Ok(Some(ResponseData {
                        message: "Data Inserted".to_string(),
                        user: Option::from(user),
                        data: None,
                    })),
                    Err(err) => {
                        error!("An error occurred in the while trying to insert user into the db in the create_user function. The error: {:?}", err);
                        Ok(Some(ResponseData {
                            message: "User Failed to be Inserted".to_string(),
                            user: None,
                            data: None,
                        }))
                    }
                }
            }
            Err(err) => {
                error!("An error occurred in the while trying to insert user into the db in the create_user function. The error: {:?}", err);
                Ok(Some(ResponseData {
                    message: "User Failed to be Inserted".to_string(),
                    user: None,
                    data: None,
                }))
            }
        }
    }

    async fn get_db_conn(
        &self,
    ) -> Result<Object<AsyncDieselConnectionManager<AsyncPgConnection>>, AuthenticationError> {
        self.pool
            .get()
            .await
            .map_err(AuthenticationError::AsyncDatabaseError)
    }

    pub async fn verify_user_password(
        &self,
        req_body: LoginUserSchema,
    ) -> Result<Option<ResponseData>, AuthenticationError> {
        let user_username = req_body.username.unwrap_or_else(|| "".to_owned());
        let user_email = req_body.email.unwrap_or_else(|| "".to_owned());
        let user_phone = req_body.phone.unwrap_or_else(|| "".to_owned());

        let check_if_user_exist = self
            .find_user_by_username_or_email_or_phone(&user_username, &user_email, &user_phone)
            .await;

        match check_if_user_exist {
            Ok(Some(user_exist)) => {
                let parsed_hash = PasswordHash::new(&user_exist.password)?;
                Argon2::default()
                    .verify_password(req_body.password.as_bytes(), &parsed_hash)
                    .map_err(|e| match e {
                        argon2::password_hash::Error::Password => IncorrectPassword,
                        _ => AuthenticationError::Argon2Error(e),
                    })?;
                Ok(Some(ResponseData {
                    message: "User Password Verified".to_string(),
                    user: None,
                    data: Some(user_exist),
                }))
            }
            Ok(None) => Ok(Some(ResponseData {
                message: "User Not Found".to_string(),
                user: None,
                data: None,
            })),
            Err(err) => {
                error!("An error occurred in the while trying to verify user password. Couldn't acquire db connection. The verify_user_password function. The error: {:?}", err);
                Err(AuthenticationError::DBConnectionError)
            }
        }
    }

    pub async fn update_email_verification_things(
        &self,
        mut data: User,
        token: u32,
        confirmed: bool,
    ) -> Result<Option<User>, AuthenticationError> {
        data.confirm_email_token = if token == 0 { None } else { Some(token as i32) };
        data.confirmed_email = Some(confirmed);
        let mut conn = self.get_db_conn().await?;
        match diesel::update(users.filter(email.eq(&data.email)))
            .set(&data)
            .returning((
                uuid_id,
                email,
                username,
                phone,
                password,
                confirmed_email,
                confirm_email_token,
                confirmed_phone,
                confirm_phone_token,
                current_available_funds,
                created_at,
                updated_at,
            ))
            .get_result::<User>(&mut conn)
            .await
        {
            Ok(user) => Ok(Some(user)),
            Err(err) => {
                error!(
                    "An error occurred in the update_email_verification_token function. The error: {}",
                    err.to_string()
                );
                Err(UserDoesNotExist)
            }
        }
    }
}
