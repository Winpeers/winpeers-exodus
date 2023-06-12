use crate::model::token_claims::{TokenClaims, TokenDetails};
use base64::engine::general_purpose;
use base64::Engine;
use uuid::Uuid;

pub fn generate_jwt_token(
    user_email: String,
    ttl: i32,
    private_key: String,
) -> Result<TokenDetails, jsonwebtoken::errors::Error> {
    let bytes_private_key = general_purpose::STANDARD.decode(private_key).unwrap();
    let decoded_private_key = String::from_utf8(bytes_private_key).unwrap();

    let now = chrono::Utc::now();
    let mut token_details = TokenDetails {
        user_email,
        token_uuid: Uuid::new_v4(),
        expires_in: Some((now + chrono::Duration::minutes(ttl as i64)).timestamp()),
        token: None,
    };

    let claims = TokenClaims {
        sub: token_details.user_email.to_string(),
        token_uuid: token_details.token_uuid.to_string(),
        iat: now.timestamp() as usize,
        exp: token_details.expires_in.unwrap() as usize,
        nbf: now.timestamp() as usize,
    };

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    let token = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(decoded_private_key.as_bytes())?,
    )?;
    token_details.token = Some(token);
    Ok(token_details)
}

pub fn verify_jwt_token(
    public_key: String,
    token: &str,
) -> Result<TokenDetails, jsonwebtoken::errors::Error> {
    let bytes_public_key = general_purpose::STANDARD.decode(public_key).unwrap();
    let decoded_public_key = String::from_utf8(bytes_public_key).unwrap();

    let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    let decoded_validation = jsonwebtoken::decode::<TokenClaims>(
        token,
        &jsonwebtoken::DecodingKey::from_rsa_pem(decoded_public_key.as_bytes())?,
        &validation,
    )?;

    let user_email = decoded_validation.claims.sub;
    let token_uuid = Uuid::parse_str(decoded_validation.claims.token_uuid.as_str()).unwrap();

    Ok(TokenDetails {
        token: None,
        token_uuid,
        user_email,
        expires_in: None,
    })
}
