use crate::{Review, Role, User};
use anyhow::{anyhow, bail};
use derive_more::Display;
use futures::executor::block_on;
use inquire::{Confirm, CustomType, max_length, Password, PasswordDisplayMode, Select, Text};
use strum::{EnumIter, IntoEnumIterator};
use crate::utils::authorization::is_authorized;
use crate::utils::input_validation::{is_name_valid, is_number_in_range, is_password_valid, is_text_length_valid, SHORT_TEXT_MAX_SIZE, REVIEW_MAX_GRADE, REVIEW_MAX_SIZE, REVIEW_MIN_GRADE, REVIEW_MIN_SIZE, PASS_DEFAULT_SCORE};
use crate::utils::password::{checked_password, hash_password};

enum ShouldContinue {
    Yes,
    No,
}

pub fn start() {
    loop_menu(main_menu);
}

fn loop_menu<F>(menu_handler: F)
    where
        F: Fn() -> ShouldContinue,
{
    loop {
        match menu_handler() {
            ShouldContinue::Yes => continue,
            ShouldContinue::No => break,
        }
    }
}

fn main_menu() -> ShouldContinue {
    #[derive(EnumIter, Display)]
    enum Choice {
        #[display(fmt = "Se connecter")]
        Login,

        #[display(fmt = "S'inscrire")]
        Register,

        #[display(fmt = "Quitter")]
        Exit,
    }

    let choice = Select::new("Que voulez-vous faire ?", Choice::iter().collect())
        .prompt()
        .unwrap();

    match choice {
        Choice::Login => login(),
        Choice::Register => register(),
        Choice::Exit => ShouldContinue::No,
    }
}

fn login() -> ShouldContinue {
    let username = Text::new("Entrez votre nom d'utilisateur : ")
        .with_validator(is_name_valid)
        .prompt()
        .unwrap();
    let password = Password::new("Entrez votre mot de passe: ")
        .with_validator(max_length!(SHORT_TEXT_MAX_SIZE, "Le mot de passe doit contenir au plus 64 caractères"))
        .without_confirmation()
        .prompt()
        .unwrap();

    let user = User::get(&username).unwrap_or_else(|| {
        //No collision since input validation does not allow empty string
        User::new("", "", Role::Reviewer)
    });
    let name = if user.name.is_empty() { None } else { Some(&*user.name) };
    let result = checked_password(name, &user.password, &password);

    if result {
        loop_menu(|| user_menu(&user));
    } else {
        println!("Le nom d'utilisateur ou le mot de passe est incorrect");
    }

    ShouldContinue::Yes
}

fn register() -> ShouldContinue {
    let username = Text::new("Entrez votre nom d'utilisateur : ")
        .with_validator(is_name_valid)
        .prompt()
        .unwrap();

    let cloned_username = username.clone();
    let password = Password::new("Entrez votre mot de passe : ")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_custom_confirmation_message("Confirmez votre mot de passe : ")
        .with_custom_confirmation_error_message("Les mots de passe ne correspondent pas")
        .with_validator(move |input: &str| is_password_valid(&cloned_username, input, PASS_DEFAULT_SCORE))
        .prompt()
        .unwrap();
    let is_owner = Confirm::new("Êtes-vous propriétaire d'un établissement ?")
        .with_default(false)
        .prompt()
        .unwrap();

    let role = if is_owner {
        let owned_establishment = Text::new("Entrez le nom de votre établissement : ")
            .with_validator(is_name_valid)
            .prompt()
            .unwrap();
        Role::Owner {
            owned_establishment,
        }
    } else {
        Role::Reviewer
    };

    let hashed_password = hash_password(password.as_bytes());
    let user = User::new(&username, &hashed_password, role);
    let _ = user.save();

    ShouldContinue::Yes
}

// -----------------------------------------------------------------------------------------------

fn user_menu(user: &User) -> ShouldContinue {
    #[derive(EnumIter, Display)]
    enum Choice {
        #[display(fmt = "Mes avis")]
        ListOwnReviews,

        #[display(fmt = "Ajouter un avis")]
        AddReview,

        #[display(fmt = "Avis d'un établissement")]
        ListEstablishmentReviews,

        #[display(fmt = "Supprimer un avis")]
        DeleteReview,

        #[display(fmt = "Se déconnecter")]
        Logout,
    }

    let choice = match Select::new("Que voulez-vous faire ?", Choice::iter().collect()).prompt() {
        Ok(choice) => choice,
        Err(..) => return ShouldContinue::Yes,
    };

    match choice {
        Choice::ListOwnReviews => list_own_reviews(user),
        Choice::AddReview => add_review(user).unwrap_or_else(|e| {
            println!("{}", e);
            ShouldContinue::Yes
        }),
        Choice::ListEstablishmentReviews => list_establishment_reviews(user),
        Choice::DeleteReview => delete_review(user).unwrap_or_else(|e| {
            println!("{}", e);
            ShouldContinue::Yes
        }),
        Choice::Logout => ShouldContinue::No,
    }
}

fn list_own_reviews(user: &User) -> ShouldContinue {
    for review in Review::by(&user.name) {
        println!("{}", review);
    }

    ShouldContinue::Yes
}

fn add_review(user: &User) -> anyhow::Result<ShouldContinue> {
    let establishment = Text::new("Entrez le nom de l'établissement : ").prompt()?;

    if !block_on(is_authorized(&user, &establishment, "review")) {
        bail!("vous n'êtes pas autorisé à ajouter un avis sur cet établissement")
    }

    let comment = Text::new("Entrez votre commentaire : ")
        .with_validator(|input: &str| is_text_length_valid(input, REVIEW_MIN_SIZE, REVIEW_MAX_SIZE))
        .prompt()?;
    let grade = CustomType::new("Entrez votre note : ")
        .with_validator(|input: &u8| is_number_in_range(input, REVIEW_MIN_GRADE, REVIEW_MAX_GRADE))
        .prompt()?;
    let review = Review::new(&establishment, &user.name, &comment, grade);

    review.save()?;

    Ok(ShouldContinue::Yes)
}

fn list_establishment_reviews(user: &User) -> ShouldContinue {
    let establishment = Text::new("Entrez le nom de l'établissement : ")
        .with_validator(is_name_valid)
        .prompt()
        .unwrap();

    let binding = Review::of(&establishment);
    let reviews: Vec<&Review> = binding.iter()
        .filter(|review| block_on(is_authorized(&user, &review.reviewer, "read")) ||
            block_on(is_authorized(&user, &review.establishment, "read")))
        .collect();

    if reviews.is_empty() {
        println!("Aucun avis trouvé");
    }

    for review in reviews {
        println!("{}", review);
    }

    ShouldContinue::Yes
}

fn delete_review(_user: &User) -> anyhow::Result<ShouldContinue> {
    if !block_on(is_authorized(&_user, "any", "delete")) {
        bail!("vous n'êtes pas administrateur")
    }

    let establishment = Text::new("Entrez le nom de l'établissement : ")
        .with_validator(is_name_valid)
        .prompt()?;

    let name = Text::new("Entrez le nom de l'auteur de l'avis : ")
        .with_validator(is_name_valid)
        .prompt()?;
    let review = Review::get(&name, &establishment).ok_or(anyhow!("avis manquant"))?;

    review.delete();

    Ok(ShouldContinue::Yes)
}
