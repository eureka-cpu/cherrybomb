use std::f32::consts::E;

use super::*;
use colored::*;
use impl_active_checks;
use mapper::digest::Method::POST;
use reqwest::Client;
use serde_json::json;
use url::Url;
 
const LIST_PARAM: [&str; 84] = [
    "page",
    "url",
    "ret",
    "r2",
    "img",
    "u",
    "return",
    "r",
    "URL",
    "next",
    "redirect",
    "redirectBack",
    "AuthState",
    "referer",
    "redir",
    "l",
    "aspxerrorpath",
    "image_path",
    "ActionCodeURL",
    "return_url",
    "link",
    "q",
    "location",
    "ReturnUrl",
    "uri",
    "referrer",
    "returnUrl",
    "forward",
    "file",
    "rb",
    "end_display",
    "urlact",
    "from",
    "goto",
    "path",
    "redirect_url",
    "old",
    "pathlocation",
    "successTarget",
    "returnURL",
    "urlsito",
    "newurl",
    "Url",
    "back",
    "retour",
    "odkazujuca_linka",
    "r_link",
    "cur_url",
    "H_name",
    "ref",
    "topic",
    "resource",
    "returnTo",
    "home",
    "node",
    "sUrl",
    "href",
    "linkurl",
    "returnto",
    "redirecturl",
    "SL",
    "st",
    "errorUrl",
    "media",
    "destination",
    "targeturl",
    "return_to",
    "cancel_url",
    "doc",
    "GO",
    "ReturnTo",
    "anything",
    "FileName",
    "logoutRedirectURL",
    "list",
    "startUrl",
    "service",
    "redirect_to",
    "end_url",
    "_next",
    "noSuchEntryRedirect",
    "context",
    "returnurl",
    "ref_url",
];

pub fn change_payload(orig: &Value, path: &[String], new_val: Value) -> Value {
    let mut change = &mut json!(null);
    let mut ret = orig.clone();
    for path_part in path.iter() {
        change = &mut ret[path_part];
    }
    *change = new_val;
    ret.clone()
}
impl<T: OAS + Serialize> ActiveScan<T> {
    
    pub async fn check_open_redirect(&self, auth: &Authorization) -> CheckRet {
        let mut ret_val: Vec<(ResponseData, AttackResponse)> = vec![];
        let mut attack_log: AttackLog = AttackLog::default();
        for base_url in self.oas.servers().unwrap_or_default() {
            for (path, item) in &self.oas.get_paths() {
                for (m, op) in item.get_ops() {
                    if m == Method::GET {
                        for i in op.params().iter() {
                            let parameter = i.inner(&Value::Null).name.to_string();
                            if LIST_PARAM.contains(&parameter.as_str()) {
                                let req = AttackRequest::builder()
                                    .uri(&base_url.url, path)
                                    .parameters(vec![RequestParameter {
                                        name: parameter.to_string(),
                                        value: "https://blst.security.com".to_string(),
                                        dm: QuePay::Query,
                                    }])
                                    .auth(auth.clone())
                                    .method(m)
                                    .headers(vec![])
                                    .auth(auth.clone())
                                    .build();
                                println!("{}", req.path);
                                if let Ok(res) = req.send_request(true).await {
                                    //logging
                                    //logging request/response/description
                                    attack_log.push(&req, &res, "Test open redirect".to_string());
                                    let res_data = ResponseData {
                                        location: path.to_string(),
                                        alert_text: format!(
                                            "The  API seems to be vulnerable to open-redirect"
                                        ),
                                    };
                                    ret_val.push((res_data, res.clone()));
                                    println!(
                                        "{}:{}",
                                        "Status".green().bold(),
                                        res.status.to_string().magenta()
                                    );
                                } else {
                                    println!("REQUEST FAILED");
                                }
                            }
                        }
                    }
                }
            }
        }
        (ret_val, attack_log)
    }
}