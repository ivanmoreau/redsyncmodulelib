//! # Redsynclib
//!
//! This is the portable library for the Redsync Library. It can be compiled
//! down to wasm (to be used in browser) or tho native code for os-level
//! clients. Do what you want with it as long as it is allowed by the license.

use hmac::Hmac;
use hkdf::Hkdf;
use reqwest::header::CONTENT_TYPE;
use serde::{Serialize, Deserialize};
use sha2::Sha256;
use pbkdf2::pbkdf2;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

const NAMESPACE: &str = "identity.mozilla.com/picl/v1/";
// https://token.services.mozilla.com/1.0/sync/1.5
const PBKDF2_ROUNDS: u32 = 1000;
const STRETCHED_PASS_LENGTH_BYTES: usize = 32;

const HKDF_SALT: &[u8] = &[0];
const HKDF_LENGTH: usize = 32;

#[cfg(target_arch = "wasm32")]
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

fn kw(name: &str) -> String {
    let r = NAMESPACE.to_owned() + name;
    r
}

fn kwe(name: &str, email: &str) -> String {
    let r = NAMESPACE.to_owned() + name + ":" + email;
    r
}

#[derive(Debug)]
#[allow(non_camel_case_types, non_snake_case)]
struct CredentialsResult {
    emailUTF8: String,
    authPW: [u8; HKDF_LENGTH],
    unwrapBKey: [u8; HKDF_LENGTH]
}

fn setup_credentials(email_input: &str, password_input: &str) -> CredentialsResult {
    let email = kwe("quickStretch", email_input).into_bytes();
    let password = password_input.to_owned().into_bytes();
    let a = derive_pbkdf2::<STRETCHED_PASS_LENGTH_BYTES>(&password, &email, PBKDF2_ROUNDS);
    let b = derive_hkdf::<HKDF_LENGTH>(&a, &kw("authPW").into_bytes(), HKDF_SALT);
    let c = derive_hkdf::<HKDF_LENGTH>(&a, &kw("unwrapBkey").into_bytes(), HKDF_SALT);
    CredentialsResult { 
        emailUTF8: email_input.to_owned(), 
        authPW: b, 
        unwrapBKey: c 
    }
}

fn derive_pbkdf2<const LENGTH: usize>(password: &[u8], email: &[u8], rounds: u32) -> [u8; LENGTH] {
    //let password_hash = Pbkdf2.hash_password(password, email).unwrap();
    let mut res = [0u8; LENGTH];
    pbkdf2::<Hmac<Sha256>>(password, email, rounds, &mut res);
    res
}

fn derive_hkdf<const LENGTH: usize>(ikm: &[u8], info: &[u8], salt: &[u8]) -> [u8; LENGTH] {
    let h = Hkdf::<Sha256>::new(Some(&salt[..]), &ikm);
    let mut okm = [0u8; LENGTH];
    h.expand(&info, &mut okm).unwrap();
    okm
}

fn u8slice2hexstr(u: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    for byte in u {
        write!(&mut s, "{:02X}", byte).expect("Unable to write");
    }
    s.to_ascii_lowercase()
}

#[derive(Serialize)]
#[allow(non_camel_case_types, non_snake_case)]
struct TokenRequest<'a>{
    email: String,
    authPW: String,
    keys: bool,
    reason: &'a str,
    verificationMethod: &'a str
}

#[derive(Serialize, Deserialize)]
#[allow(non_camel_case_types, non_snake_case)]
struct TokenResponse {
    uid: String,
    sessionToken: String,
    keyFetchToken: String,
    verified: bool,
    unwrapBKey: String
}

/// This function fetches the keyFetchToken from the auth server.
/// It is the first expected to be used in the library. From
/// there, you will have to inform the user about verification, and
/// then you should be able to continue. We only return the
/// bare minimal for the next function. If error, this returns
/// a message with the error instead of the TokenResponse.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub async fn get_key_fetch_token(usr: String, pw: String) -> String {
    let t = setup_credentials(&usr, &pw);
    let data = TokenRequest {
        email: t.emailUTF8,
        authPW: u8slice2hexstr(&t.authPW),
        keys: true,
        reason: "login",
        verificationMethod: "email"
    };
    let client = reqwest::Client::new();
    let body = client
    .post("https://api.accounts.firefox.com/v1/account/login?keys=true")
    .json(&data)
    .send()
    .await
    .unwrap()
    .text()
    .await
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    match v["error"] {
        serde_json::Value::String(_) => {
            return serde_json::to_string(v["message"].as_str().unwrap()).unwrap();
        },
        _ => {}
    }
    let response = TokenResponse {
        uid: v["uid"].as_str().unwrap().to_string(),
        sessionToken: v["sessionToken"].as_str().unwrap().to_string(),
        keyFetchToken: v["keyFetchToken"].as_str().unwrap().to_string(),
        verified: v["verified"].as_bool().unwrap(),
        unwrapBKey: u8slice2hexstr(&t.unwrapBKey)
    };
    serde_json::to_string(&response).unwrap()
}

///   This will:
///
/// - Fetch the account keys, required to access the Sync data later.
/// - Create an OAuth token for the given client ID and scope, this is
///   the easiest way of authenticating to Sync and the alternative BrowserID
///   method that doesn't require a OAuth token is deprecated.
/// - Get the scoped key data that is used to compute the `X-KeyID` header.
/// - Authenticate to the TokenServer to get a Sync token.
/// - Derive the Sync key bundle from the Sync key.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub async fn get_creds(tokenr: String /* TokenResponse */) -> String {
    let client = reqwest::Client::new();
    let body = client
    .post("https://proyecto.ivmoreau.com/login2")
    .header(CONTENT_TYPE, "application/json")
    .body(tokenr)
    .send()
    .await
    .unwrap()
    .text()
    .await
    .unwrap();
    body
}

/// This function fetches every element for the specified collection.
/// You should provide the data as a JSON string with the following
/// structure:
/// ```JSON
/// {
///     "creds": "structure of credentials",
///     "collection": "collection"
/// }
/// ```
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub async fn get_collection(payload: String) -> String {
    let client = reqwest::Client::new();
    let body = client
    .post("https://proyecto.ivmoreau.com/getCollection")
    .header(CONTENT_TYPE, "application/json")
    .body(payload)
    .send()
    .await
    .unwrap()
    .text()
    .await
    .unwrap();
    body
}

/// This function updates/creates every element for the specified
/// collection. You should provide the data as a JSON string with
/// the following structure:
/// ```JSON
/// {
///     "creds": "structure of credentials",
///     "collection": "collection",
///     "payload": "array of BSOs as specified by the FxAPI"
/// }
/// ```
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub async fn up_items_collection(payload: String) -> String {
    let client = reqwest::Client::new();
    let body = client
    .post("https://proyecto.ivmoreau.com/upItemsCollection")
    .header(CONTENT_TYPE, "application/json")
    .body(payload)
    .send()
    .await
    .unwrap()
    .text()
    .await
    .unwrap();
    body
}

#[cfg(test)]
mod tests {
    use crate::{kwe, u8slice2hexstr};

    #[test]
    fn kwe_test() {
        let res = kwe("name", "email");
        assert_eq!(res, "identity.mozilla.com/picl/v1/name:email");
    }

    #[test]
    fn setup_credentials_test() {
        let kreds = crate::setup_credentials(
            "andré@example.org", "pässwörd"
        );
        assert_eq!(u8slice2hexstr(&kreds.authPW), 
            "247b675ffb4c46310bc87e26d712153abe5e1c90ef00a4784594f97ef54f2375"
        );
        assert_eq!(u8slice2hexstr(&kreds.unwrapBKey), 
            "de6a2648b78284fcb9ffa81ba95803309cfba7af583c01a8a1a63e567234dd28"
        );
    }
}