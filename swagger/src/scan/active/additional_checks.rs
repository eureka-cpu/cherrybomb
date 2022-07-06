use std::f32::consts::E;

use super::*;
use colored::*;
use impl_active_checks;
use mapper::digest::Method::POST;
use reqwest::Client;
use serde_json::json;
use url::Url;

pub fn change_payload(orig: &Value, path: &[String], new_val: Value) -> Value {
    let mut change = &mut json!(null);
    let mut ret = orig.clone();
    for path_part in path.iter() {
        change = &mut ret[path_part];
    }
    *change = new_val;
    ret.clone()
}
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
    pub async fn check_parameter_pollution(&self, auth: &Authorization) -> (CheckRet, Vec<String>) {
        let mut ret_val: Vec<(ResponseData, AttackResponse)> = vec![];
        let mut attack_log: AttackLog = AttackLog::default();
        let server = self.oas.servers();
        //    let mut new_url:(String , String);
        let mut vec_polluted = vec!["blstparamtopollute".to_string()];
        for base_url in server.unwrap_or_default() {
            for (path, item) in &self.oas.get_paths() {
                for (m, op) in item.get_ops() {
                    let _text = path.to_string();
                    //   println!("{:?}", text);
                    if m == Method::GET {
                        for i in op.params().iter_mut() {
                            let parameter = i.inner(&Value::Null);
                            let in_var = parameter.param_in.to_string();
                            let param_name = i.inner(&Value::Null).name.to_string();
                            let new_param = param_name.clone();
                            let param_example = match in_var.as_str() {
                                "query" => {
                                    let req = AttackRequest::builder()
                                        .uri(&base_url.url, &path)
                                        .auth(auth.clone())
                                        .parameters(vec![
                                            RequestParameter {
                                                name: param_name,
                                                value: "blstparamtopollute".to_string(),
                                                dm: QuePay::Query,
                                            },
                                            RequestParameter {
                                                name: new_param,
                                                value: "blstparamtopollute".to_string(),
                                                dm: QuePay::Query,
                                            },
                                        ])
                                        .method(m)
                                        .headers(vec![])
                                        .auth(auth.clone())
                                        .build();
                                    if let Ok(res) = req.send_request(true).await {
                                        //logging request/response/description
                                        attack_log.push(
                                            &req,
                                            &res,
                                            "Test parameter pollution".to_string(),
                                        );
                                        let res_data = ResponseData {
                                            location: path.to_string(),
                                            alert_text: format!(
                                                "The  is not enforced by the server"
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
                                "path" => {}
                                _ => (),
                                //    if m == Method::POST {
                                // for i in op.params().iter_mut() {
                                //     println!("This is a post request");
                                //     let parameter = i.inner(&Value::Null);
                                //     let in_var = parameter.param_in.to_string();
                                //     let param_name = i.inner(&Value::Null).name.to_string();
                                //     let new_param = param_name.clone();

                                // }
                            };
                        }
                    }
                }
            }
        }
        ((ret_val, attack_log), vec_polluted)
    }
    pub async fn check_post_parameter_pollution(
        &self,
        auth: &Authorization,
    ) -> (CheckRet, Vec<String>) {
        let mut ret_val: Vec<(ResponseData, AttackResponse)> = vec![];
        let mut attack_log: AttackLog = AttackLog::default();
        let mut vec_polluted = vec!["blstparamtopollute".to_string()];
        for (path, ( payload, map)) in &self.static_props {
         //   dbg!(&payload);
            for (json_path, schema) in map {
                let mut test_vals: Vec<_> = vec![];
             //   dbg!(&json_path);
                if let Some(ex) = &schema.example {
                    test_vals.push(ex);
                    println!("{}", ex);
                }
                for val in test_vals.iter() {
                    if let Some(url) =
                        get_path_urls(self.oas.get_paths().get(path).unwrap(), self.oas.servers())
                            .iter() //to change maybe to the beginning; 
                            .find(|&&(method, _)| method == POST)
                    {
                        println!("PAYLOAD: ===>{:?}", payload);
                        for i in payload.as_object().unwrap(){
                            println!("{:?}",i);
                        }
                        
                        
                    }
                }
            }
        }
        ((ret_val, attack_log), vec_polluted)
    }
}
