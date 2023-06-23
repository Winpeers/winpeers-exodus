use lazy_static::lazy_static;
use rusoto_ses::{Destination, SendTemplatedEmailRequest, Ses, SesClient};
use std::error::Error;

lazy_static! {
    static ref SES_CLIENT: SesClient = SesClient::new(rusoto_core::Region::EuNorth1);
}

pub async fn send_welcome_email(first_name: &str, to: &str) -> Result<(), Box<dyn Error>> {
    let destination = Destination {
        to_addresses: Some(vec![to.to_string()]),
        ..Default::default()
    };

    let ses_request = SendTemplatedEmailRequest {
        destination,
        source: "Winpeers <winpeershq@gmail.com>".to_string(),
        template: "Winpeers_Welcome_Email_Template".to_string(),
        template_data: format!("{{ \"firstname\":\"{}\" }}", first_name),
        ..Default::default()
    };

    SES_CLIENT
        .send_templated_email(ses_request)
        .await
        .map_err(|e| format!("The error: {:?}", e))
        .expect("error sending mail");

    Ok(())
}

pub async fn send_email_verify_mail(
    first_name: &str,
    to: &str,
    ran_num: u32,
) -> Result<(), Box<dyn Error>> {
    let destination = Destination {
        to_addresses: Some(vec![to.to_string()]),
        ..Default::default()
    };
    // let ran_num = generate_random_number().await;

    let ses_request = SendTemplatedEmailRequest {
        destination,
        source: "Winpeers <winpeershq@gmail.com>".to_string(),
        template: "Winpeers_Verify_Email_Template".to_string(),
        template_data: format!(
            "{{ \"firstname\":\"{}\", \"token\":\"{}\" }}",
            first_name, ran_num
        ),
        ..Default::default()
    };

    SES_CLIENT
        .send_templated_email(ses_request)
        .await
        .map_err(|e| format!("The error: {:?}", e))
        .expect("error sending mail");

    Ok(())
}

pub async fn send_password_reset_mail(
    first_name: &str,
    to: &str,
    ran_num: u32,
) -> Result<(), Box<dyn Error>> {
    let destination = Destination {
        to_addresses: Some(vec![to.to_string()]),
        ..Default::default()
    };
    // let ran_num = generate_random_number().await;

    let ses_request = SendTemplatedEmailRequest {
        destination,
        source: "Winpeers <winpeershq@gmail.com>".to_string(),
        template: "Winpeers_Reset_Password_Email_Template".to_string(),
        template_data: format!(
            "{{ \"firstname\":\"{}\", \"token\":\"{}\" }}",
            first_name, ran_num
        ),
        ..Default::default()
    };

    SES_CLIENT
        .send_templated_email(ses_request)
        .await
        .map_err(|e| format!("The error: {:?}", e))
        .expect("error sending mail");

    Ok(())
}
