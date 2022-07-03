use std::f32::consts::E;

use super::*;
use reqwest::Client;
use serde_json::json;
use mapper::digest::Method::POST;
use colored::*;
use impl_active_checks;
use url::Url;

pub fn change_payload(orig:& Value,path:&[String],new_val:Value)->Value{
    let mut change=&mut json!(null);
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
            for (json_path, schema) in map {
                let mut test_vals: Vec<_> = vec![];
                if let Some(min) = schema.minimum {
                    test_vals.push(("minimum", min - 1));                }
                if let Some(max) = schema.maximum {
                    test_vals.push(("maximum", max + 1));
                }
                for val in test_vals.iter() {
                    if let Some(url) = get_path_urls(self.oas.get_paths().get(path).unwrap(),
                                                     self.oas.servers()).iter().find(|&&(method, _)| method == POST) {
                        let req = AttackRequest::builder()
                            .uri(&url.1, path)
                            .method(url.0)
                            .headers(vec![])
                            .parameters(vec![])
                            .auth(auth.clone())
                            .payload( &change_payload(payload,json_path,json!(val.1)).to_string())
                            .build();
                        if let Ok(res) = req.send_request(true).await {
                            //logging request/response/description
                            attack_log.push(&req,&res,"Testing min/max values".to_string());
                            let res_data = ResponseData {
                                location: path.clone(),
                                alert_text: format!("The {} for {} is not enforced by the server", val.0, json_path[json_path.len() - 1]),
                            };
                            ret_val.push((
                                res_data,
                                res.clone()
                            ));
                          //  println!("{}:{}","Status".green().bold(),res.status.to_string().magenta());
                        } else {
                            //println!("REQUEST FAILED");
                        }
                    }
                }
            }
        }
        (ret_val,attack_log)
    }
    pub async fn check_string_length_max(&self, auth: &Authorization) -> CheckRet {
            let mut ret_val: Vec<(ResponseData, AttackResponse)> = vec![];
            let mut attack_log: AttackLog = AttackLog::default();
            for (path, (payload, map)) in &self.static_props {
                for (json_path, schema) in map {
                    let mut test_vals: Vec<_> = vec![];
                    if let Some(string_length) = schema.max_length {
                      let mut  str_to_push: String  = create_string(string_length);
                        test_vals.push(str_to_push);
                    }
                    for val in test_vals.iter() {
                        if let Some(url) = get_path_urls(self.oas.get_paths().get(path).unwrap(),
                                                         self.oas.servers()).iter().find(|&&(method, _)| method == POST) {
                            let req = AttackRequest::builder()
                                .uri(&url.1,"")
                                .method(url.0)
                                .headers(vec![])
                                .parameters(vec![])
                                .auth(auth.clone())
                                .payload( &change_payload(payload,json_path,json!(val)).to_string())
                                .build();
                            if let Ok(res) = req.send_request(true).await {
                                //logging request/response/description
                                attack_log.push(&req,&res,"Testing min/max values".to_string());
                                let res_data = ResponseData {
                                    location: path.clone(),
                                    alert_text: format!("The {} for {} is not enforced by the server", val, json_path[json_path.len() - 1]),
                                };
                                ret_val.push((
                                    res_data,
                                    res.clone()
                                ));
                                println!("{}:{}","Status".green().bold(),res.status.to_string().magenta());
                            } else {
                                println!("REQUEST FAILED");
                            }
                        }
                    }
                }
            }
            (ret_val,attack_log)
        
    }
    pub async fn check_ssl(&self, auth: &Authorization) -> CheckRet {
        let mut ret_val: Vec<(ResponseData, AttackResponse)> = vec![];
        let mut attack_log: AttackLog = AttackLog::default();
         if let  Some(server_url)  = self.oas.servers(){
                for   i in server_url {
                    let format_url = create_http_url(i.url);
                    let req = AttackRequest::builder()
                    .uri(&format_url,"")
                    .auth(auth.clone())
                    .build();
                if let Ok(res) = req.send_request(true).await {
                    //logging request/response/description
                    attack_log.push(&req,&res,"Testing min/max values".to_string());
                    let res_data = ResponseData {
                        location: format_url,
                        alert_text: format!("The  is not enforced by the server"),
                    };
                    ret_val.push((
                        res_data,
                        res.clone()
                    ));
                    println!("{}:{}","Status".green().bold(),res.status.to_string().magenta());
                } else {
                    println!("REQUEST FAILED");
                }



                }
         }
     
        (ret_val,attack_log)
    }
    pub async fn check_parameter_pollution(&self, auth: &Authorization) -> (CheckRet,String) {
        let mut ret_val: Vec<(ResponseData, AttackResponse)> = vec![];
        let mut attack_log: AttackLog = AttackLog::default();
        let server = self.oas.servers();
        for base_url in server.unwrap(){
            for (path, item) in &self.oas.get_paths() {
                for (m, op) in item.get_ops() {
                    let text = path.to_string();
                    println!("{:?}", text);
                    if m==Method::GET {
                        for i in op.params().iter_mut() {
                            let parameter = i.inner(&Value::Null);
                            let in_var = parameter.param_in.to_string();
                            let param_name = parameter.name.to_string();
                            match in_var.as_str() {
    
                                "query" => {
                                    let elem  = (param_name,"petstotest");
                                    let params = [
                                        elem
                                    ];
                                let new_url = create_url_with_parameter(&params, path.to_string()); 
                                                         
    
                                let req = AttackRequest::builder()
                                //.uri(&new_url,"")
                                .uri(&base_url.url,&new_url)
                                .auth(auth.clone())
                                .method(m)
                                .headers(vec![])
                                .auth(auth.clone())
                                .build();
                            if let Ok(res) = req.send_request(true).await {
                                //logging request/response/description
                                attack_log.push(&req,&res,"Test parameter pollution".to_string());
                                let res_data = ResponseData {
                                    location: path.to_string(),
                                    alert_text: format!("The  is not enforced by the server"),
                                };
                                ret_val.push((
                                    res_data,
                                    res.clone()
                                ));
                                println!("{}:{}","Status".green().bold(),res.status.to_string().magenta());
                            } else {
                                println!("REQUEST FAILED");
                            }
                                },
                                "path" => {},
                                _=>()
                             }
                        }
                    }
                    /* match m {
                        Method::GET => alerts.extend(Self::get_check(&op.security, path)) */
                }
            }
        }
        

(ret_val,attack_log, new_url.1)


    }
 
}   

