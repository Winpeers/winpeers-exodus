use dotenv::dotenv;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_expires_in: String,
    pub jwt_max_age: i32,
}

impl Config {
    pub fn init() -> Config {
        dotenv().ok();
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        let jwt_expires_in = std::env::var("JWT_EXPIRES_IN").expect("JWT_EXPIRES_IN must be set");
        let jwt_max_age = std::env::var("JWT_MAX_AGE")
            .unwrap_or_else(|_| String::new());

        let jwt_max_age = if jwt_max_age.is_empty() {
            3600 // Default value of 3600 if environment variable is not set
        } else {
            jwt_max_age.parse::<i32>().expect("Failed to parse JWT_MAX_AGE as i32")
        };

        Config {
            database_url,
            jwt_secret,
            jwt_expires_in,
            jwt_max_age
        }
    }
}