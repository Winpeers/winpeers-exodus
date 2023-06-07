use crate::config::config::Config;
use crate::models::user::LoginUserSchema;
use crate::models::{
    schema::{
        todos::dsl::todos,
        users::{dsl::users, email, password, phone, username},
    },
    todo::Todo,
    user::{RegisterUserSchema, User},
};
use crate::repository::database::AuthenticationError::IncorrectPassword;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::Utc;
use deadpool::managed::Object;
use diesel::{BoolExpressionMethods, ExpressionMethods, OptionalExtension, QueryDsl};
use diesel_async::{
    pooled_connection::{deadpool::Pool, AsyncDieselConnectionManager},
    AsyncPgConnection, RunQueryDsl,
};
use log::error;
use rand_core::OsRng;
use std::error::Error as StdError;

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
    IncorrectPassword,
    NoUsernameSet,
    NoPasswordSet,
    Argon2Error(argon2::password_hash::Error),
    DatabaseError(diesel::result::Error),
    AsyncDatabaseError(diesel_async::pooled_connection::deadpool::PoolError),
    DBConnectionError,
}

impl From<argon2::password_hash::Error> for AuthenticationError {
    fn from(err: argon2::password_hash::Error) -> Self {
        AuthenticationError::Argon2Error(err)
    }
}

impl Database {
    pub fn new() -> Self {
        let config = Config::init();
        let manager = AsyncDieselConnectionManager::<diesel_async::AsyncPgConnection>::new(
            config.database_url,
        );
        let pool = Pool::builder(manager)
            .build()
            .expect("Failed to create pool.");
        Database { pool }
    }

    async fn find_user_by_username_or_email_or_phone(
        &self,
        user_name: &str,
        user_email: &str,
        user_phone: &str,
    ) -> Result<Option<RegisterUserSchema>, AuthenticationError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(AuthenticationError::AsyncDatabaseError)?;
        let exists = users
            .filter(
                username
                    .eq(user_name)
                    .or(email.eq(user_email))
                    .or(phone.eq(user_phone)),
            )
            .select((username, email, phone, password))
            .first::<(String, String, Option<String>, String)>(&mut conn)
            .await
            .optional()
            .map_err(AuthenticationError::DatabaseError)?;

        if let Some((user__name, user__email, user__phone, user__password)) = exists {
            let user = RegisterUserSchema {
                username: user__name,
                email: user__email,
                phone: user__phone,
                password: user__password,
            };
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    pub async fn create_user(&self, req_body: RegisterUserSchema) -> ResponseData {
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
        let mut conn = match self.pool.get().await {
            Ok(conn) => conn,
            Err(err) => {
                error!("An error occurred. The error: {:?}", err);
                return ResponseData {
                    message: "Can't acquire connection to db".to_string(),
                    user: None,
                    data: None,
                };
                // return ResponseData {"Can't acquire connection to db".massage: "".to_string(), to_owned(), None, user: None };
            }
        };
        match user_exists {
            Ok(Some(_)) => ResponseData {
                message: "Data Exists".to_string(),
                user: None,
                data: None,
            },
            Ok(None) => {
                let salt = SaltString::generate(&mut OsRng);
                let hashed_password = Argon2::default()
                    .hash_password(req_body.password.as_bytes(), &salt)
                    .expect("Error while hashing password")
                    .to_string();

                let user = User {
                    uuid: uuid::Uuid::new_v4().to_string(),
                    email: req_body.email.to_string(),
                    username: req_body.username.to_string(),
                    phone: Some(user_phone),
                    password: hashed_password,
                    confirmed_email: None,
                    confirm_email_token: None,
                    confirmed_phone: None,
                    confirm_phone_token: None,
                    current_available_funds: 0,
                    created_at: Some(Utc::now().naive_utc()),
                    updated_at: Some(Utc::now().naive_utc()),
                };

                match diesel::insert_into(users)
                    .values(&user)
                    .execute(&mut conn)
                    .await
                {
                    Ok(_) => ResponseData {
                        message: "Data Inserted".to_string(),
                        user: Option::from(user),
                        data: None,
                    },
                    Err(err) => {
                        error!("An error occurred in the while trying to insert user into the db in the create_user function. The error: {:?}", err);
                        ResponseData {
                            message: "User Failed to be Inserted".to_string(),
                            user: None,
                            data: None,
                        }
                    }
                }
            }
            Err(err) => {
                error!("An error occurred in the while trying to insert user into the db in the create_user function. The error: {:?}", err);
                ResponseData {
                    message: "User Failed to be Inserted".to_string(),
                    user: None,
                    data: None,
                }
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
        // let mut conn = self.get_db_conn().await?;
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

    pub async fn create_todo(&self, todo: Todo) -> Result<Todo, Box<dyn StdError>> {
        let todo = Todo {
            id: uuid::Uuid::new_v4().to_string(),
            created_at: Some(Utc::now().naive_utc()),
            updated_at: Some(Utc::now().naive_utc()),
            ..todo
        };

        let mut conn = self.pool.get().await.map_err(Box::new)?;

        diesel::insert_into(todos)
            .values(&todo)
            .execute(&mut conn)
            // .expect("Error creating new todo")
            .await
            .map_err(Box::new)?;
        Ok(todo)
    }

    pub async fn get_todos(&self) -> Result<Vec<Todo>, Box<dyn StdError>> {
        let mut conn = self.pool.get().await.map_err(Box::new)?;
        Ok(todos.load::<Todo>(&mut conn).await.map_err(Box::new)?)
    }

    pub async fn get_todos_by_id(&self, todo_id: &str) -> Option<Todo> {
        let mut conn = match self.pool.get().await {
            Ok(conn) => conn,
            Err(err) => {
                //log the error then return None
                error!("An error occurred. The error: {:?}", err);
                // println!("Error: {:?}", err);
                return None;
            }
        };
        let todo = match todos.find(todo_id).get_result::<Todo>(&mut conn).await {
            Ok(todo) => todo,
            Err(err) => {
                //log the error then return None
                error!(
                    "An error occurred in the get_todos_by_id function. The error: {}",
                    err.to_string()
                );
                // println!("the second error: {}", err.to_string());
                return None;
            }
        };

        Some(todo)
    }

    pub async fn update_todo_by_id(&self, todo_id: &str, mut todo: Todo) -> Option<Todo> {
        let mut conn = match self.pool.get().await {
            Ok(conn) => conn,
            Err(err) => {
                //log the error then return None
                error!("An error occurred. The error: {:?}", err);
                // println!("Error: {:?}", err);
                return None;
            }
        };
        todo.updated_at = Some(Utc::now().naive_utc());
        let todo = match diesel::update(todos.find(todo_id))
            .set(&todo)
            .get_result::<Todo>(&mut conn)
            .await
        {
            Ok(todo) => todo,
            Err(err) => {
                //log the error then return None
                error!(
                    "An error occurred in the update_todo_by_id function. The error: {}",
                    err.to_string()
                );
                // println!("the third error: {}", err.to_string());
                return None;
            }
        };

        Some(todo)
    }

    pub async fn delete_todo_by_id(&self, todo_id: &str) -> Option<usize> {
        let mut conn = match self.pool.get().await {
            Ok(conn) => conn,
            Err(err) => {
                //log the error then return None
                error!("An error occurred. The error: {:?}", err);
                // println!("Error: {:?}", err);
                return None;
            }
        };
        let count = match diesel::delete(todos.find(todo_id)).execute(&mut conn).await {
            Ok(count) => count,
            Err(err) => {
                //log the error then return None
                error!(
                    "An error occurred in the update_todo_by_id function. The error: {}",
                    err.to_string()
                );
                // println!("the fourth error: {}", err.to_string());
                return None;
            }
        };

        Some(count)
    }
}
