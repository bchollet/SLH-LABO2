use inquire::CustomUserError;
use inquire::validator::{Validation};
use inquire::validator::Validation::{Invalid, Valid};
use zxcvbn::zxcvbn;
use regex::Regex;
use serde::de::StdError;

pub const PASS_MIN_SIZE: usize = 8;
pub const PASS_MAX_SIZE: usize = 64;
pub const NAME_MAX_SIZE: usize = 63;
pub const REVIEW_MIN_SIZE: usize = 1;
pub const REVIEW_MAX_SIZE: usize = 650;
pub const REVIEW_MIN_GRADE: u8 = 1;
pub const REVIEW_MAX_GRADE: u8 = 5;

pub fn is_name_valid(name: &str) -> Result<Validation, CustomUserError> {
    let regex_str = r"^[a-zA-Z0-9À-ÖØ-öø-ÿ]+(?:\s[a-zA-Z0-9À-ÖØ-öø-ÿ]+)*$";
    let regex = Regex::new(regex_str).unwrap();
    if regex.is_match(name) && name.chars().count() <= NAME_MAX_SIZE {
        return Ok(Valid);
    }
    Ok(Invalid("Le nom entré est invalide".into()))
}

pub fn is_text_length_valid(input: &str, lower_bound: usize, upper_bound: usize) -> Result<Validation, CustomUserError> {
    if lower_bound >= upper_bound {
        return Ok(Invalid("Mauvaise utilisation: La borne inf. doit être plus petite que la borne sup.".into()));
    }
    if input.chars().count() > upper_bound {
        return Ok(Invalid("est trop long".into()));
    }
    if input.chars().count() < lower_bound {
        return Ok(Invalid("est trop court".into()));
    }
    Ok(Valid)
}

pub fn is_number_in_range(input: &u8, lower_bound: u8, upper_bound: u8) -> Result<Validation, CustomUserError> {
    if lower_bound >= upper_bound {
        return Ok(Invalid("Mauvaise utilisation: La borne inf. doit être plus petite que la borne sup.".into()));
    }
    if input > &upper_bound {
        return Ok(Invalid("Le chiffre est trop grand".into()));
    }
    if input < &lower_bound {
        return Ok(Invalid("Le chiffre est trop petit".into()));
    }
    Ok(Valid)
}

pub fn is_password_valid(username: &str, password: &str, score_lower_bound: u8) -> Result<Validation, CustomUserError> {
    let inputs = [username];
    let estimate = zxcvbn(password, &inputs).unwrap().score();
    if estimate <= score_lower_bound {
        return Ok(Invalid("Le mot de passe n'est pas assez fort".into()));
    }
    Ok(Valid)
}

// ------------------ UNIT TESTS --------------------------

#[cfg(test)]
mod tests {
    use inquire::validator::Validation::{Invalid, Valid};
    use crate::utils::input_validation::{is_name_valid, is_number_in_range, is_password_valid, is_text_length_valid};


    #[test]
    fn is_short_text_length_valid_returns_ok_if_length_valid() {
        //Given
        let lb = 8;
        let ub = 64;
        let input = String::from("I am supposed to be valid");
        //When
        let result = is_text_length_valid(&input, lb, ub);
        //Then
        assert_eq!(result.unwrap(), Valid)
    }

    #[test]
    fn is_short_text_length_valid_returns_err_if_wrong_usage() {
        //Given
        let lb = 64;
        let ub = 8;
        let input = String::from("Whatever");
        //When
        let result = is_text_length_valid(&input, lb, ub);
        //Then
        assert_eq!(result.unwrap(), Invalid("Mauvaise utilisation: La borne inf. doit être plus petite que la borne sup.".into()))
    }

    #[test]
    fn is_short_text_length_valid_returns_err_if_length_invalid() {
        //Given
        let lb = 8;
        let ub = 64;
        let input = "Invalid";
        let input2 = "Yay, I am also invalid, but this time it is because I am too long";
        //When
        let result = is_text_length_valid(input, lb, ub);
        let result2 = is_text_length_valid(input2, lb, ub);
        //Then
        assert_eq!(result.unwrap(), Invalid("est trop court".into()).into());
        assert_eq!(result2.unwrap(), Invalid("est trop long".into()));
    }

    #[test]
    fn is_number_in_range_returns_ok_if_valid() {
        //Given
        let lb = 0;
        let ub = 10;
        let input = 5;
        //When
        let result = is_number_in_range(&input, lb, ub);
        //Then
        assert_eq!(result.unwrap(), Valid);
    }

    #[test]
    fn is_number_in_range_returns_err_if_invalid() {
        //Given
        let lb = 1;
        let ub = 10;
        let input = 11;
        let input2 = 0;
        //When
        let result = is_number_in_range(&input, lb, ub);
        let result2 = is_number_in_range(&input2, lb, ub);
        //Then
        assert_eq!(result.unwrap(), Invalid("Le chiffre est trop grand".into()));
        assert_eq!(result2.unwrap(), Invalid("Le chiffre est trop petit".into()));
    }

    #[test]
    fn is_number_in_range_returns_err_if_wrong_usage() {
        //Given
        let lb = 10;
        let ub = 1;
        let input = 5;
        //When
        let result = is_number_in_range(&input, lb, ub);
        //Then
        assert_eq!(result.unwrap(), Invalid("Mauvaise utilisation: La borne inf. doit être plus petite que la borne sup.".into()));
    }

    #[test]
    fn is_password_valid_returns_ok_if_valid() {
        //Given
        let username = "toto";
        let pass = "Argent1234!";
        let pass2 = "4a-hSb_nf@°sd#jkBf";
        let pass3 = "a4Jlp$qwz";
        //When
        let result = is_password_valid(username, pass, 2);
        let result2 = is_password_valid(username, pass2, 2);
        let result3 = is_password_valid(username, pass3, 2);
        //Then
        assert_eq!(result.unwrap(), Valid);
        assert_eq!(result2.unwrap(), Valid);
        assert_eq!(result3.unwrap(), Valid);
    }

    #[test]
    fn is_password_valid_returns_err_if_not_strong_enough() {
        //Given
        let username = "Àlex4ndr3 B1jOux";
        let pass = "ArthurDent1";
        let pass2 = "Platypus";
        let pass3 = "egj@as?!";
        let pass4 = "Àlex4ndr3 B1jOux";
        //When
        let result = is_password_valid(username, pass, 2);
        let result2 = is_password_valid(username, pass2, 2);
        let result3 = is_password_valid(username, pass3, 2);
        let result4 = is_password_valid(username, pass4, 2);
        //Then
        assert_eq!(result.unwrap(), Invalid("Le mot de passe n'est pas assez fort".into()));
        assert_eq!(result2.unwrap(), Invalid("Le mot de passe n'est pas assez fort".into()));
        assert_eq!(result3.unwrap(), Invalid("Le mot de passe n'est pas assez fort".into()));
        assert_eq!(result4.unwrap(), Invalid("Le mot de passe n'est pas assez fort".into()));
    }

    #[test]
    fn is_name_valid_returns_ok_if_valid() {
        //Given
        let name = "a"; //bare minimum
        let name2 = "Alexandre"; //One name
        let name3 = "François Àräbíatã"; //with special char
        let name4 = "Solène Von Gunten"; //with multiple spaces
        let expected = Valid;
        //When
        let result = is_name_valid(name);
        let result2 = is_name_valid(name2);
        let result3 = is_name_valid(name3);
        let result4 = is_name_valid(name4);
        //Then
        assert_eq!(result.unwrap(), expected);
        assert_eq!(result2.unwrap(), expected);
        assert_eq!(result3.unwrap(), expected);
        assert_eq!(result4.unwrap(), expected);
    }
    #[test]
    fn is_name_valid_returns_err_if_invalid() {
        //Given
        let name = "";
        let name2 = "     "; //spaces alone not authorized
        let name3 = "Alan "; //spaces not authorized if not between chars
        let name4 = " Marcus"; //spaces not authorized if not between chars
        let name5 = "Bṓris"; //invalid special char
        let name6 = "ahlfshkdshfoiwjlkdmslvndlkfhgisjlmfsdlsadasdasdasdassdlkjfdkfgjkdsnfjkknkejdsdgjsiodhgsdp"; //too long
        let expected = Invalid("Le nom entré est invalide".into());
        //When
        let result = is_name_valid(name);
        let result2 = is_name_valid(name2);
        let result3 = is_name_valid(name3);
        let result4 = is_name_valid(name4);
        let result5 = is_name_valid(name5);
        let result6 = is_name_valid(name6);
        //Then
        assert_eq!(result.unwrap(), expected);
        assert_eq!(result2.unwrap(), expected);
        assert_eq!(result3.unwrap(), expected);
        assert_eq!(result4.unwrap(), expected);
        assert_eq!(result5.unwrap(), expected);
        assert_eq!(result6.unwrap(), expected);
    }
}