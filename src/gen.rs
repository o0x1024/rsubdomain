
use std::collections::VecDeque;
use itertools::Itertools;

pub fn generate_subdomains(domains: &[&str],suffix:Vec<&str>) -> Vec<String> {

    // let domains_no_suffix = domains.iter().map(|x|x.replace("mgtv.com", "")).collect();
    let mut subdomains = Vec::new();
    for domain in domains {
        let mut domain_without_suffix = String::new();
        for suf in suffix.clone(){
            if domain.contains(suf){
                domain_without_suffix = domain.replace(suf, "");
            }
        }
        let parts: VecDeque<_> = domain_without_suffix.split('.').collect();
        for i in 1..=parts.len() {
            for combo in parts.clone().into_iter().combinations(i) {
                let subdomain = combo.join(".");
                subdomains.push(subdomain);
            }
        }
    }
    subdomains
}




#[cfg(test)]
mod tests {
    use super::*;
    use strsim::{levenshtein,jaro_winkler};


    #[test]
    fn string_match(){
        let s1 = "static2-scloud-letv.yysh.mgtv.com";
        let s2 = "static2-abc-letv.yysh.mgtv.com";
        let distance = jaro_winkler(s1, s2);
        println!("Levenshtein distance: {}", distance);
    }

    #[test]
    fn internal() {
        let domains = &[
            "tuyere.api.mgtv.com",
            "node-ssl.titan.mgtv.com",
            "static2-scloud-letv.yysh.mgtv.com",
            "static2-scloud-letv.yysh.mgtv.com.cdnle.com",
            "hisense-download-juui-plugin.yysh.mgtv.com",
            "hisense-download-juui-plugin.yysh.mgtv.com.wsdvs.com",
            "hisense-paster-thirdcmp.yysh.mgtv.com",
            "paster-thirdcmp.hismarttv.com",
            "mgemsg3.api.mgtv.com",
            "al2z.gateway.mgtv.com",
            "hisense-all-jhxkt.yysh.mgtv.com",
            "all-jhxkt.hismarttv.com"
    
        ];
        let suffix = vec![".mgtv.com",".hismarttv.com"];
        let subdomains = generate_subdomains(domains,suffix);
        println!("{:?}", subdomains);
    }
}
