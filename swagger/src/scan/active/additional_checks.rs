use std::f32::consts::E;

use super::*;
use colored::*;
use impl_active_checks;
use mapper::digest::Method::POST;
use reqwest::{Client, StatusCode};
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

 

impl<T: OAS + Serialize> ActiveScan<T> {
    pub async fn check_method_permissions(&self, auth: &Authorization) -> (CheckRet) {
        let mut ret_val: Vec<(ResponseData, AttackResponse)> = vec![];
        let mut attack_log: AttackLog = AttackLog::default();
        for (path, item) in &self.oas.get_paths() {
            //counter 
            //len 
            let mut request_map: HashMap<Method, bool> = HashMap::new();
           request_map.insert(Method::GET.to_string(), false);
            request_map.insert(Method::POST.to_string(), false);
           request_map.insert(Method::DELETE.to_string(), false);

            for (m, op) in item.get_ops() {
                println!("{:?}",item.get_ops());
                match m {
                    Method::GET => {
                        //hashmap create 
                        request_map[&Method::GET] = true;

                        

                    },
                    Method::PUT => {
                        request_map[&Method::PUT] = true;

                    },
                    Method::POST => {
                       request_map[&Method::GET] = true;
                    }
                    _=>(),

                };
               let iter =request_map.iter().filter(|&(_, v)| v != &true);
                for i in iter{
                    let value_to_add = send_request(i.0, path,auth, attack_log);
                    attack_log.push(value_to_add.1);
                    ret_val.push(value_to_add.0);
                    
                    }
                }
                    
                
            }
            (ret_val,attack_log)
        
        }


    
    }
    pub fn send_request( m: Method, p: path ,auth: Authorization, logs: AttackLog)-> CheckRet{
        let mut ret_val: Vec<(ResponseData, AttackResponse)> = vec![];

        
        let req = AttackRequest::builder()
                .uri(&url, p)
                .auth(auth.clone())
                .method(m)
                .headers(vec![])
                .auth(auth.clone())
                .build();
            println!("{}", req.path);
            if let Ok(res) = req.send_request(true).await {
                //logging
                //logging request/response/description
                log.push(&req, &res, "Test method permission".to_string());
                let res_data = ResponseData {
                    location: p.to_string(),
                    alert_text: format!(
                        "The endpoint seems to be misconfigured, and {} are possible on this endpoint",p
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
            (ret_val,log)
        }
     

                

    
