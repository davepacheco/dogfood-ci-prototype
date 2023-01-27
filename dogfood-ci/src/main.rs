// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Prototype program that uses the Oxide API for a CI system
//! The goal of this program is to derisk the plan for using an Oxide system for
//! buildomat-based CI.

use anyhow::anyhow;
use anyhow::Context;
use clap::Parser;
use oauth2::TokenResponse;
use oxide_client::ClientHiddenExt;

#[derive(Parser)]
struct Args {
    pub url: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    let api_url = url::Url::parse(&args.url)
        .with_context(|| format!("parse url {:?}", args.url))?;

    // Use OAuth to get a token.
    let authorize_url = {
        let mut url = api_url.clone();
        url.set_path("/authorize");
        oauth2::AuthUrl::new(url.into()).context("making authorization url")?
    };
    let device_auth_url = {
        let mut url = api_url.clone();
        url.set_path("/device/auth");
        oauth2::DeviceAuthorizationUrl::new(url.into())
            .context("making device authorization url")?
    };
    let token_url = {
        let mut url = api_url.clone();
        url.set_path("/device/token");
        oauth2::TokenUrl::new(url.into()).context("making token url")?
    };

    let client_id = oauth2::ClientId::new(uuid::Uuid::new_v4().to_string());
    let oauth_client = oauth2::basic::BasicClient::new(
        client_id,
        None,
        authorize_url,
        Some(token_url),
    )
    .set_auth_type(oauth2::AuthType::RequestBody)
    .set_device_authorization_url(device_auth_url);

    let details: oauth2::devicecode::StandardDeviceAuthorizationResponse =
        oauth_client
            .exchange_device_code()
            .context("exchanging device code")?
            .request_async(oauth2::reqwest::async_http_client)
            .await?;

    println!(
        "please open in browser: {}",
        details
            .verification_uri_complete()
            .ok_or_else(|| anyhow!("expected complete verification uri"))?
            .secret()
    );
    println!("enter user code: {}", details.user_code().secret());

    let token_response = oauth_client
        .exchange_device_access_token(&details)
        .request_async(
            oauth2::reqwest::async_http_client,
            tokio::time::sleep,
            None,
        )
        .await?;
    println!(
        "received token: {}",
        token_response.access_token().secret().to_string()
    );

    // Make an authenticated request using this token.
    let authn_headers = {
        let mut headers = reqwest::header::HeaderMap::new();
        let mut val = reqwest::header::HeaderValue::from_str(&format!(
            "Bearer {}",
            token_response.access_token().secret().to_string()
        ))
        .context("making bearer token header")?;
        val.set_sensitive(true);
        headers.insert(http::header::AUTHORIZATION, val);
        headers
    };
    let reqwest_client = reqwest::Client::builder()
        .default_headers(authn_headers)
        .build()
        .context("failed to make reqwest client")?;
    let api_client =
        oxide_client::Client::new_with_client(api_url.as_str(), reqwest_client);

    let v = api_client
        .session_me()
        .send()
        .await
        .context("failed to fetch /session/me")?;
    println!("authenticated as:");
    println!("    user id      {:?}", v.id);
    println!("    display name {:?}", v.display_name);

    Ok(())
}
