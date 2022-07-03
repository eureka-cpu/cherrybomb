use super::*;

impl<T: OAS + Serialize> ActiveScan<T> {
    pub fn not_2xx(check_ret: CheckRet) -> (Vec<Alert>, AttackLog) {
        let mut ret_val = vec![];
        for (res_data, response) in check_ret.0.into_iter() {
            if (200..300u16).contains(&response.status) {
                ret_val.push(Alert::with_certainty(
                    Level::Low,
                    res_data.alert_text,
                    res_data.location,
                    Certainty::Certain,
                ))
            }
        }
        (ret_val, check_ret.1)
    }
    pub fn reflected_and_2xx(check_ret: CheckRet, keyword: String ) -> (Vec<Alert>, AttackLog) {
        let mut ret_val = vec![];
        for (res_data, response) in check_ret.0.into_iter() {
            if (200..300u16).contains(&response.status) {
                if response.payload.contains(&keyword){
                    ret_val.push(Alert::with_certainty(
                        Level::Medium,
                        res_data.alert_text,
                        res_data.location,
                        Certainty::Certain,
                    )) 
                }
    }
}
    (ret_val, check_ret.1)
}
}
