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
            _ => req
                .peer_addr()
                .ok_or_else(|| {
                    SimpleKeyExtractionError::new("Could not extract peer IP address from request")
                })
                .map(|socket| socket.ip()),
        }
    }

    #[cfg(feature = "log")]
    fn key_name(&self, key: &Self::Key) -> Option<String> {
        Some(key.to_owned())
    }
}
