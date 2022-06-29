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
    pub async fn check_min_max(&self, auth: &Authorization) -> CheckRet {
        let mut ret_val: Vec<(ResponseData, AttackResponse)> = vec![];
        let mut attack_log: AttackLog = AttackLog::default();
        for (path, (payload, map)) in &self.static_props {
            //dbg!(payload);
            for (json_path, schema) in map {
                let mut test_vals: Vec<_> = vec![];
                dbg!(schema);
                if let Some(min) = schema.minimum {
                    //  println!("This is min :{}",min);
                    test_vals.push(("minimum", min - 1));
                }
                if let Some(max) = schema.maximum {
                    test_vals.push(("maximum", max + 1));
                }
                for val in test_vals.iter() {
                    if let Some(url) =
                        get_path_urls(self.oas.get_paths().get(path).unwrap(), self.oas.servers())
                            .iter()
                            .find(|&&(method, _)| method == POST)
                    {
                        let req = AttackRequest::builder()
                            .uri(&url.1, path)
                            .method(url.0)
                            .headers(vec![])
                            .parameters(vec![])
                            .auth(auth.clone())
                            .payload(&change_payload(payload, json_path, json!(val.1)).to_string())
                            .build();
                        if let Ok(res) = req.send_request(true).await {
                            //logging request/response/description
                            attack_log.push(&req, &res, "Testing min/max values".to_string());
                            let res_data = ResponseData {
                                location: path.clone(),
                                alert_text: format!(
                                    "The {} for {} is not enforced by the server",
                                    val.0,
                                    json_path[json_path.len() - 1]
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
        (ret_val, attack_log)
    }
    pub async fn check_string_length_max(&self, auth: &Authorization) -> CheckRet {
        let mut ret_val: Vec<(ResponseData, AttackResponse)> = vec![];
        let mut attack_log: AttackLog = AttackLog::default();
        for (path, (payload, map)) in &self.static_props {
            //dbg!(payload);
            for (json_path, schema) in map {
                let mut test_vals: Vec<_> = vec![];
                //   dbg!(schema);
                if let Some(string_length) = schema.max_length {
                    //  println!("This is min :{}",min);
                    let mut str_to_push: String = create_string(string_length);

                    test_vals.push(str_to_push);
                }
                for val in test_vals.iter() {
                    if let Some(url) =
                        get_path_urls(self.oas.get_paths().get(path).unwrap(), self.oas.servers())
                            .iter()
                            .find(|&&(method, _)| method == POST)
                    {
                        let req = AttackRequest::builder()
                            .uri(&url.1, path)
                            .method(url.0)
                            .headers(vec![])
                            .parameters(vec![])
                            .auth(auth.clone())
                            .payload(&change_payload(payload, json_path, json!(val)).to_string())
                            .build();
                        if let Ok(res) = req.send_request(true).await {
                            //logging request/response/description
                            attack_log.push(&req, &res, "Testing min/max values".to_string());
                            let res_data = ResponseData {
                                location: path.clone(),
                                alert_text: format!(
                                    "The {} for {} is not enforced by the server",
                                    val,
                                    json_path[json_path.len() - 1]
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
        (ret_val, attack_log)
    }
}
// pub fn CreateString ( num: i64)-> String {
//     let mut str = String::from("");
//     for n in  0..num+1{
//         println!("{:?}",n);
//        str.push_str("a");
//     }
//     str
// }
