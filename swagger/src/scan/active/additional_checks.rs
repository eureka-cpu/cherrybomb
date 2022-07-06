use super::*;
use colored::*;
use impl_active_checks;
use mapper::digest::Method::POST;
use serde_json::json;

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
    pub async fn check_ssl(&self, auth: &Authorization) -> CheckRet {
        let mut ret_val: Vec<(ResponseData, AttackResponse)> = vec![];
        let mut attack_log: AttackLog = AttackLog::default();
        if let Some(server_url) = self.oas.servers() {
            for i in server_url {
                // let format_url = create_http_url(i.url);
                let new_url = i.url.clone();
                //    let format_u  = &new_url[..5];
                //&new_url[..5]="http";
                let req = AttackRequest::builder()
                    .uri(&new_url, "")
                    .auth(auth.clone())
                    .build();
                if let Ok(res) = req.send_request(true).await {
                    //logging request/response/description
                    attack_log.push(&req, &res, "Testing min/max values".to_string());
                    let res_data = ResponseData {
                        location: new_url,
                        alert_text: format!("The  is not enforced by the server"),
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

        (ret_val, attack_log)
    }
}