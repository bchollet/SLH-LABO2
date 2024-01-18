use argon2::{Config, verify_encoded};
use rand::Rng;

fn generate_salt() -> String {
    let mut rng = rand::thread_rng();
    let salt: Vec<u8> = (0..16).map(|_| rng.gen::<u8>()).collect();

    // Convert the salt bytes to a hexadecimal string
    let hex_string: String = salt.iter().map(|byte| format!("{:02x}", byte)).collect();

    hex_string
}

pub fn hash_password(password: &[u8]) -> String {
    let salt = generate_salt();
    argon2::hash_encoded(password, salt.as_ref(), &Config::default()).unwrap()
}

pub fn checked_password(username: Option<&str>, hash: &str, password: &str) -> bool {
    const DEFAULT_PASS: &str = "dedce41f-a89c-4f98-8107-ea26bc83752a";
    match username {
        None => {
            let _ = verify_encoded(DEFAULT_PASS, DEFAULT_PASS.as_ref());
            false
        }
        Some(_) => {
            verify_encoded(hash, password.as_ref()).unwrap()
        }
    }
}

// ------------------ UNIT TESTS --------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_salt() {
        // Test that the generated salt has the correct length
        let salt = generate_salt();
        assert_eq!(salt.len(), 32);  // 16 bytes converted to a 32-character hexadecimal string
    }

    #[test]
    fn test_hash_password() {
        // Test that hash_password produces a non-empty string
        let password = b"my_password";
        let hashed_password = hash_password(password);
        let hashed_password2 = hash_password(password);
        assert!(!hashed_password.is_empty());
        // The same password should have a different hash
        assert_ne!(hashed_password, hashed_password2);
    }

    #[test]
    fn test_checked_password() {
        // Test case when the user is not found (None)
        assert!(!checked_password(None, "hash", "password"));

        // Test case when the user is found (Some)
        let name = Some("existing@example.com");
        let password = "correct_password";
        let hash = hash_password(password.as_bytes());

        assert!(checked_password(name, &hash, password));
    }
}