extern crate jsonwebtoken as jwt;
extern crate serde;
extern crate serde_json;
#[macro_use] extern crate serde_derive;
extern crate base64;
extern crate chrono;

use chrono::Utc;

use jwt::{encode, decode, Header, Algorithm, Validation};

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
use pam::constants::{PamResultCode, PamFlag, PAM_PROMPT_ECHO_ON};
use pam::conv::PamConv;
use std::ffi::CStr;

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
            Err(e) => {
                println!("Error: {}", e);
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

fn get_device_config() -> Result<DeviceConfig, serde_json::Error> {
    let mut file = File::open("/mnt/boot/config.json").unwrap();
    let mut buff = String::new();
    file.read_to_string(&mut buff).unwrap();

    return serde_json::from_str(&buff);
}

impl PamHooks for PamJWT {  

    // This function performs the task of authenticating the user.
    fn sm_authenticate(pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {

        let user = pam_try!(pamh.get_user(None));

        let conv = match pamh.get_item::<PamConv>() {
            Ok(conv) => conv,
            Err(err) => {
                println!("Couldn't get pam_conv");
                return err;
            }
        };

        let device_config = unwrap_or_fail!(get_device_config());
        let public_key = unwrap_or_fail!(base64::decode(&device_config.public_key));

        // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiNjFhNThmNTZjMWM5YzhiN2FjMTcxZGEwMDZjNWRlY2UiLCJ1c2VyIjoicm9vdCIsImV4cCI6MjUzMjUyNDg5MX0.DFilfga7bvzV8knkSaPWjzhYwwlt_iIXAs0zi7aCQJs
        println!("== Start JWT Auth ==");
        
        let token = match pam_try!(conv.send(PAM_PROMPT_ECHO_ON, "Bearer: ")) {
            None => "".to_owned(),
            Some(t) => t
        };
        // let my_claims = Claims {
        //     uuid: "4d3643dc035c6e659242a63339523549".to_owned(),
        //     user: "root".to_owned(),
        //     exp: Utc::now().timestamp() + 10000,
        // };
        // let token = encode(&Header::new(Algorithm::RS256), &my_claims, include_bytes!("../conf/private_key.der")).unwrap();

        println!("token: {}", token);

        let token_data = unwrap_or_fail!(decode::<Claims>(&token, &public_key, &Validation::new(Algorithm::RS256)));

        if token_data.claims.user != user {
            return PamResultCode::PAM_AUTH_ERR;
        }

        if token_data.claims.uuid != device_config.uuid {
            return PamResultCode::PAM_AUTH_ERR;
        }

        println!("== End JWT Auth ==");

        return PamResultCode::PAM_SUCCESS;
    }

    fn sm_setcred(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("set credentials");
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("account management");
        PamResultCode::PAM_SUCCESS
    }
}
