use crate::AppState;
use actix_governor::{KeyExtractor, SimpleKeyExtractionError};
use actix_web::dev::ServiceRequest;
use actix_web::web;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct RealIpKeyExtractor;

impl KeyExtractor for RealIpKeyExtractor {
    type Key = IpAddr;
    type KeyExtractionError = SimpleKeyExtractionError<&'static str>;

    #[cfg(feature = "log")]
    fn name(&self) -> &'static str {
        "real IP"
    }

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        // Get the reverse proxy IP that we put in app data
        let reverse_proxy_ip = req
            .app_data::<web::Data<AppState>>()
            .map(|ip| ip.trusted_reverse_proxy_ip.to_owned())
            .unwrap_or_else(|| IpAddr::from_str("0.0.0.0").unwrap());

        let peer_ip = req.peer_addr().map(|socket| socket.ip());
        let connection_info = req.connection_info();

        match peer_ip {
            // The request is coming from the reverse proxy, we can trust the `Forwarded` or `X-Forwarded-For` headers
            Some(peer) if peer == reverse_proxy_ip => connection_info
                .realip_remote_addr()
                .ok_or_else(|| {
                    SimpleKeyExtractionError::new("Could not extract real IP address from request")
                })
                .and_then(|str| {
                    SocketAddr::from_str(str)
                        .map(|socket| socket.ip())
                        .or_else(|_| IpAddr::from_str(str))
                        .map_err(|_| {
                            SimpleKeyExtractionError::new(
                                "Could not extract real IP address from request",
                            )
                        })
                }),
            // The request is not coming from the reverse proxy, we use peer IP
            _ => connection_info
                .peer_addr()
                .ok_or_else(|| {
                    SimpleKeyExtractionError::new("Could not extract peer IP address from request")
                })
                .and_then(|str| {
                    SocketAddr::from_str(str).map_err(|_| {
                        SimpleKeyExtractionError::new(
                            "Could not extract peer IP address from request",
                        )
                    })
                })
                .map(|socket| socket.ip()),
        }
        // let data = req.app_data::<web::Data<AppState>>().unwrap();
        //
        // let access_token = if let Some(cookie) = req.cookie("access_token") {
        //     Some(cookie.value().to_string())
        // } else {
        //     req.headers()
        //         .get(http::header::AUTHORIZATION)
        //         .and_then(|header| header.to_str().ok())
        //         .filter(|header| !header.is_empty())
        //         .and_then(|header| {
        //             if header.starts_with("Bearer ") {
        //                 Some(header[7..].to_string())
        //             } else {
        //                 None
        //             }
        //         })
        // };
        //
        // let access_t = match access_token {
        //     Some(token) => Ok(token),
        //     None => Err(AuthError(ErrorResponse {
        //         status: "failed".to_string(),
        //         message: "The token has expired (rlm)".to_string(),
        //     })),
        // };
        //
        // let access_token_details = match verify_jwt_token(
        //     data.config.access_token_public_key.to_string(),
        //     &access_t.unwrap(),
        // ) {
        //     Ok(token_details) => token_details,
        //     Err(_) => {
        //         return Err(AuthError(ErrorResponse {
        //             status: "failed".to_string(),
        //             message: "The token has expired (rlm)".to_string(),
        //         }))
        //     }
        // };
        //
        // let user_email_redis_result = async move {
        //     let redis_result = data
        //         .redis_db
        //         .get_str(&access_token_details.token_uuid.to_string())
        //         .await;
        //
        //     match redis_result {
        //         Ok(val) => Ok(val),
        //         Err(e) => {
        //             error!("The error: {:?}", e);
        //             Err(AuthError(ErrorResponse {
        //                 status: "failed".to_string(),
        //                 message: "The token has expired (rlm)".to_string(),
        //             }))
        //         }
        //     }
        // };
        //
        // match block_on(user_email_redis_result) {
        //     Ok(user_email) => Ok(user_email),
        //     Err(e) => {
        //         error!("The error: {:?}", e);
        //         Err(AuthError(ErrorResponse {
        //             status: "failed".to_string(),
        //             message: "The token has expired (rlm)".to_string(),
        //         }))
        //     }
        // }
    }

    #[cfg(feature = "log")]
    fn key_name(&self, key: &Self::Key) -> Option<String> {
        Some(key.to_owned())
    }
}
