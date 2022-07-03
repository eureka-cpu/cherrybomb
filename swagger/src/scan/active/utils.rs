use super::*;
pub fn get_path_urls(path: &PathItem, servers: Option<Vec<Server>>) -> Vec<(Method, String)> {
    let mut urls = vec![];
    let methods: Vec<Method> = path.get_ops().iter().map(|(m, _)| m).cloned().collect();
    for (m, op) in path.get_ops() {
        if let Some(servers) = &op.servers {
            urls.extend(
                servers
                    .iter()
                    .map(|s| (m, s.url.clone()))
                    .collect::<Vec<(Method, String)>>(),
            );
        }
    }
    if urls.is_empty() {
        if let Some(servers) = servers {
            for m in methods {
                urls.extend(servers.iter().map(|s| (m, s.url.clone())));
            }
        }
    }
    urls
}
pub fn create_string(num: i64) -> String {
    let mut str = String::from("");
    for n in 0..num + 1 {
        println!("{:?}", n);
        str.push_str("a");
    }
    str
}
pub fn create_http_url(url: String) -> String {
    if url.contains("https") {
        let mut split = url.split("https://");
        let vec: Vec<&str> = split.collect();
        let str = format!("{}{}", "http://", vec[1]);
        println!("THe url after format: {:?}", str);
        str

    }
    else {
        url
    }
}
pub fn create_url_with_parameter(url: &[(String, &str)], path: String) -> String {
    let mut new_url = format!("{}",path);
    let parameter_polluted = "various";
    for i in  url{
        new_url.push_str(&*format!("?{}={}" ,i.0, i.1));
        new_url.push_str(&*format!("?{}={}",i.0, parameter_polluted));
    }
    println!("New url endpoint with parameter: {} ", new_url);

    new_url
    }

