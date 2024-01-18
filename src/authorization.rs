use casbin::{CoreApi, Enforcer, MgmtApi};

pub async fn is_authorized() {
    let mut e = Enforcer::new("authorization/model.conf", "authorization/policy.csv")
        .await
        .expect("cannot read model or policy");
    e.add_policy(vec![String::from("alice"), String::from("data1"), String::from("read")])
        .await
        .expect("cannot add policy");
    // if let Ok(authorized) = e.enforce((sub, obj, act)) {
    //     if authorized {
    //         println!("Authorized!");
    //     } else {
    //         println!("Not Authorized!");
    //     }
    // } else {
    //     panic!("Error!");
    // }
}