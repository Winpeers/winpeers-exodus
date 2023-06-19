use dotenv::dotenv;

fn get_env_var(var_name: &str) -> String {
    std::env::var(var_name).unwrap_or_else(|_| panic!("{} must be set", var_name))
}

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub redis_url: String,

    pub jwt_secret: String,
    pub jwt_expires_in: String,
    pub jwt_max_age: u32,

    pub access_token_private_key: String,
    pub access_token_public_key: String,
    pub access_token_expires_in: String,
    pub access_token_max_age: u32,

    pub refresh_token_private_key: String,
    pub refresh_token_public_key: String,
    pub refresh_token_expires_in: String,
    pub refresh_token_max_age: u32,
}

impl Config {
    pub fn init() -> Config {
        dotenv().ok();
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        let jwt_expires_in = std::env::var("JWT_EXPIRES_IN").expect("JWT_EXPIRES_IN must be set");
        let jwt_max_age = std::env::var("JWT_MAX_AGE").unwrap_or_else(|_| String::new());

        let redis_url = get_env_var("REDIS_URL");

        let access_token_private_key = get_env_var("ACCESS_TOKEN_PRIVATE_KEY");
        let access_token_public_key = get_env_var("ACCESS_TOKEN_PUBLIC_KEY");
        let access_token_expires_in = get_env_var("ACCESS_TOKEN_EXPIRED_IN");
        let access_token_max_age = get_env_var("ACCESS_TOKEN_MAX_AGE");

        let refresh_token_private_key = get_env_var("REFRESH_TOKEN_PRIVATE_KEY");
        let refresh_token_public_key = get_env_var("REFRESH_TOKEN_PUBLIC_KEY");
        let refresh_token_expires_in = get_env_var("REFRESH_TOKEN_EXPIRED_IN");
        let refresh_token_max_age = get_env_var("REFRESH_TOKEN_MAX_AGE");

        let jwt_max_age = if jwt_max_age.is_empty() {
            3600 // Default value of 3600 if environment variable is not set
        } else {
            jwt_max_age
                .parse::<u32>()
                .expect("Failed to parse JWT_MAX_AGE as u32")
        };

        Config {
            database_url,
            jwt_secret,
            jwt_expires_in,
            jwt_max_age,
            redis_url,
            access_token_private_key,
            access_token_public_key,
            refresh_token_private_key,
            refresh_token_public_key,
            access_token_expires_in,
            refresh_token_expires_in,
            access_token_max_age: access_token_max_age.parse::<u32>().unwrap(),
            refresh_token_max_age: refresh_token_max_age.parse::<u32>().unwrap(),
        }
    }
}
