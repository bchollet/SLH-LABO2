use casbin::{CoreApi, Enforcer};
use crate::User;

pub async fn is_authorized(sub: &User, obj: &str, act: &str) -> bool {
    let e = Enforcer::new("authorization/model.conf", "authorization/policy.csv")
        .await
        .expect("cannot read model or policy");

    if let Ok(authorized) = e.enforce((sub, obj, act)) {
        if authorized {
            return true;
        } else {
            return false;
        }
    } else {
        panic!(r"ERROR CASBIN - BETTE CRASH THAN ALLOWING ACCESS ¯\_(ツ)_/¯");
    }
}


// ------------------ UNIT TESTS --------------------------

#[cfg(test)]
mod test {
    use futures::executor::block_on;
    use crate::{Role, User};
    use crate::utils::authorization::is_authorized;

    #[test]
    fn test_access_control() {
        let reviewer: User = User::new("reviewer", "73@Lp7xM!RDkS5ot", Role::Reviewer);

        let admin: User = User::new("admin", "73@Lp7xM!RDkS5ot", Role::Admin);

        let owner: User = User::new(
            "owner",
            "73@Lp7xM!RDkS5ot",
            Role::Owner {
                owned_establishment: "etab1".to_string(),
            },
        );

        assert!(block_on(is_authorized(&admin, "any", "read")));
        assert!(block_on(is_authorized(&admin, "any", "review")));
        assert!(block_on(is_authorized(&admin, "any", "delete")));

        assert!(!block_on(is_authorized(&reviewer, "any", "delete")));
        assert!(block_on(is_authorized(&reviewer, "any", "review")));
        assert!(block_on(is_authorized(&reviewer, "etab1", "review")));
        assert!(!block_on(is_authorized(&reviewer, "any", "read")));
        assert!(block_on(is_authorized(&reviewer, "reviewer", "read")));

        assert!(block_on(is_authorized(&owner, "owner", "read")));
        assert!(block_on(is_authorized(&owner, "etab1", "read")));
        assert!(!block_on(is_authorized(&owner, "etab2", "read")));
        assert!(!block_on(is_authorized(&owner, "etab1", "review")));
        assert!(block_on(is_authorized(&owner, "etab2", "review")));
        assert!(!block_on(is_authorized(&owner, "etab2", "delete")));
    }
}