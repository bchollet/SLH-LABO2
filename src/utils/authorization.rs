use casbin::{CoreApi, Enforcer};
use crate::User;

pub async fn is_authorized(sub: User, obj: &str, act: &str) -> bool {
    let e = Enforcer::new("authorization/model.conf", "authorization/policy.csv")
        .await
        .expect("cannot read model or policy");

    // println!("{:?}",sub);
    //
    // let toto = e.enforce((sub, obj, act));
    // match toto {
    //     Ok(val) => { println!("TOUT VA BIEN {}", val)}
    //     Err(err) => { println!("ERROR CASBIN: {}", err) }
    // }

    if let Ok(authorized) = e.enforce((sub, obj, act)) {
        if authorized {
            println!("AUTHORIZED");
            return true
        } else {
            println!("NOT AUTHORIZED");
            return false
        }
    } else {
        println!("ERROR CASBIN");
        false
    }
}