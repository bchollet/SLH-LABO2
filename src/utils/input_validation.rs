use inquire::{CustomUserError, max_length, min_length};
use inquire::validator::{StringValidator, Validation};
use inquire::validator::Validation::{Invalid, Valid};
use zxcvbn::zxcvbn;
use regex::Regex;

pub const PASS_MIN_SIZE: usize = 8;
pub const PASS_DEFAULT_SCORE: u8 = 2;
pub const SHORT_TEXT_MAX_SIZE: usize = 64;
pub const REVIEW_MIN_SIZE: usize = 1;
pub const REVIEW_MAX_SIZE: usize = 650;
pub const REVIEW_MIN_GRADE: u8 = 1;
pub const REVIEW_MAX_GRADE: u8 = 5;

pub fn is_name_valid(name: &str) -> Result<Validation, CustomUserError> {
    //Check length
    let length_valid = max_length!(SHORT_TEXT_MAX_SIZE, format!("Le nom doit contenir au plus {} caractères", SHORT_TEXT_MAX_SIZE))
        .validate(name)?;

    if length_valid == Valid {
        //Check format
        let regex_str = r"^[a-zA-Z0-9À-ÖØ-öø-ÿ]+(?:\s[a-zA-Z0-9À-ÖØ-öø-ÿ]+)*$";
        let regex = Regex::new(regex_str).unwrap();
        if !regex.is_match(name) {
            return Ok(Invalid("Le nom entré est invalide".into()));
        }
    }

    Ok(length_valid)
}

pub fn is_text_length_valid(text: &str, lower_bound: usize, upper_bound: usize) -> Result<Validation, CustomUserError> {
    if lower_bound >= upper_bound {
        return Ok(Invalid("Mauvaise utilisation: La borne inf. doit être plus petite que la borne sup.".into()));
    }

    let min_valid = min_length!(lower_bound, format!("Texte trop court (min {} caractères)", lower_bound))
        .validate(text)?;
    if min_valid != Valid {
        return Ok(min_valid);
    }
    let max_valid = max_length!(upper_bound, format!("Texte trop long (max {} caractères)", upper_bound))
        .validate(text)?;
    if max_valid != Valid {
        return Ok(max_valid);
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
    //Check length
    let max_valid = max_length!(SHORT_TEXT_MAX_SIZE, format!("Le mot de passe doit contenir au plus {} caractères", SHORT_TEXT_MAX_SIZE))
        .validate(&password)?;
    if max_valid != Valid {
        return Ok(max_valid);
    }
    let min_valid = min_length!(PASS_MIN_SIZE, format!("Le mot de passe doit contenir au moins {} caractères", PASS_MIN_SIZE))
        .validate(&password)?;
    if min_valid != Valid {
        return Ok(min_valid);
    }

    //Check strength
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
        let result = is_text_length_valid(&input, lb, ub).unwrap();
        //Then
        assert_eq!(result, Valid)
    }

    #[test]
    fn is_short_text_length_valid_returns_err_if_wrong_usage() {
        //Given
        let lb = 64;
        let ub = 8;
        let input = String::from("Whatever");
        //When
        let result = is_text_length_valid(&input, lb, ub).unwrap();
        //Then
        assert_eq!(result, Invalid("Mauvaise utilisation: La borne inf. doit être plus petite que la borne sup.".into()))
    }

    #[test]
    fn is_short_text_length_valid_returns_err_if_length_invalid() {
        //Given
        let lb = 8;
        let ub = 10;
        let input = "Invalid";
        let input2 = "Yay, I am also invalid, but this time it is because I am too long";
        //When
        let result = is_text_length_valid(&input, lb, ub).unwrap();
        let result2 = is_text_length_valid(&input2, lb, ub).unwrap();
        //Then
        assert_eq!(result, Invalid("Texte trop court (min 8 caractères)".into()));
        assert_eq!(result2, Invalid("Texte trop long (max 10 caractères)".into()));
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
        let expected_long = Invalid("Le nom doit contenir au plus 64 caractères".into());
        //When
        let result = is_name_valid(name).unwrap();
        let result2 = is_name_valid(name2).unwrap();
        let result3 = is_name_valid(name3).unwrap();
        let result4 = is_name_valid(name4).unwrap();
        let result5 = is_name_valid(name5).unwrap();
        let result6 = is_name_valid(name6).unwrap();
        //Then
        assert_eq!(result, expected);
        assert_eq!(result2, expected);
        assert_eq!(result3, expected);
        assert_eq!(result4, expected);
        assert_eq!(result5, expected);
        assert_eq!(result6, expected_long);
    }
}