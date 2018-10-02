extern crate jsonwebtoken as jwt;
extern crate serde;
extern crate serde_json;
#[macro_use] extern crate serde_derive;
extern crate base64;
extern crate chrono;

use jwt::{decode, Algorithm, Validation};

use std::fs::File;
use std::io::Read;

/// Our claims struct, it needs to derive `Serialize` and/or `Deserialize`
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    user: String,
    uuid: String,
    exp: i64,
}

#[macro_use] extern crate pam;
use pam::module::{PamHandle, PamHooks};
use pam::constants::{PamResultCode, PamFlag, PAM_PROMPT_ECHO_OFF, PAM_TEXT_INFO};
use pam::conv::PamConv;
use std::ffi::CStr;
use std::collections::HashMap;

macro_rules! pam_try {
    ($e:expr) => (
        match $e {
            Ok(v) => v,
            Err(e) => return e,
        }
    );
    ($e:expr, $err:expr) => (
        match $e {
            Ok(v) => v,
            Err(e) => {
                println!("Error: {}", e);
                return $err;
            }
        }
    );
}

macro_rules! unwrap_or_fail {
    ( $e:expr ) => {
        match $e {
            Ok(x) => x,
            Err(_) => {                
                return PamResultCode::PAM_AUTH_ERR;
            }
        }
    }
}

struct PamJWT;
pam_hooks!(PamJWT);

#[derive(Serialize, Deserialize)]
struct DeviceConfig {
    uuid: String,
    public_key: String
}

fn get_device_config(path: &str) -> Result<DeviceConfig, serde_json::Error> {
    let mut file = File::open(path).unwrap();
    let mut buff = String::new();
    file.read_to_string(&mut buff).unwrap();

    return serde_json::from_str(&buff);
}

impl PamHooks for PamJWT {

    // This function performs the task of authenticating the user.
    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {

        let args: Vec<_> = args.iter().map(|s| s.to_string_lossy().to_owned() ).collect();
        let args: HashMap<&str, &str> = args.iter().map(|s| {
            let mut parts = s.splitn(2, "=");
            (parts.next().unwrap(), parts.next().unwrap_or(""))
        }).collect();

        let device_config_path: &str = match args.get("config") {
            Some(config) => config,
            None => return PamResultCode::PAM_AUTH_ERR,
        };

        let device_config = unwrap_or_fail!(get_device_config(device_config_path));
        let public_key = unwrap_or_fail!(base64::decode(&device_config.public_key));
        
        let user = unwrap_or_fail!(pamh.get_user(None));
        let conv = unwrap_or_fail!(pamh.get_item::<PamConv>());
        
        let token = unwrap_or_fail!(conv.send(PAM_PROMPT_ECHO_OFF, "Bearer: ")).unwrap();
        let token_data = unwrap_or_fail!(decode::<Claims>(&token, &public_key, &Validation::new(Algorithm::RS256)));

        if token_data.claims.user != user {
            return PamResultCode::PAM_AUTH_ERR;
        }

        if token_data.claims.uuid != device_config.uuid {
            return PamResultCode::PAM_AUTH_ERR;
        }        

        return PamResultCode::PAM_SUCCESS;
    }

    fn sm_setcred(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {        
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }
}
