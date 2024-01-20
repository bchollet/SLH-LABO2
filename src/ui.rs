use crate::{Review, Role, User};
use anyhow::{anyhow, bail};
use casbin::{CoreApi};
use derive_more::Display;
use inquire::{Confirm, CustomType, max_length, min_length, Password, PasswordDisplayMode, Select, Text};
use inquire::validator::{StringValidator};
use strum::{EnumIter, IntoEnumIterator};
use crate::utils::input_validation::{is_name_valid, is_number_in_range, is_password_valid, is_text_length_valid, PASS_MAX_SIZE, PASS_MIN_SIZE, REVIEW_MAX_GRADE, REVIEW_MAX_SIZE, REVIEW_MIN_GRADE, REVIEW_MIN_SIZE};

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
        .prompt()?;
    let password = Password::new("Entrez votre mot de passe: ")
        .without_confirmation()
        .prompt()?;

    let user = User::get(&username).expect("l'utilisateur n'existe pas");

    if password == user.password {
        loop_menu(|| user_menu(&user));
    } else {
        println!("Le mot de passe est incorrect");
    }

    ShouldContinue::Yes
}

fn register() -> ShouldContinue {
    let username = Text::new("Entrez votre nom d'utilisateur : ")
        .with_validator(is_name_valid)
        .prompt()
        .unwrap();

    let cloned_username = username.clone();
    let validators: Vec<Box<dyn StringValidator>> = vec![
        Box::new(min_length!(PASS_MIN_SIZE, "Le mot de passe doit contenir au moins 8 caractères")),
        Box::new(max_length!(PASS_MAX_SIZE, "Le mot de passe doit contenir au plus 64 caractères")),
        Box::new(move |input: &str| is_password_valid(&cloned_username, input, 2)),
    ];

    let password = Password::new("Entrez votre mot de passe : ")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_custom_confirmation_message("Confirmez votre mot de passe : ")
        .with_custom_confirmation_error_message("Les mots de passe ne correspondent pas")
        .with_validators(&validators)
        .prompt()?;
    let is_owner = Confirm::new("Êtes-vous propriétaire d'un établissement ?")
        .with_default(false)
        .prompt()?;

    let role = if is_owner {
        let owned_establishment = Text::new("Entrez le nom de votre établissement : ")
            .with_validator(is_name_valid)
            .prompt()?;
        Role::Owner {
            owned_establishment,
        }
    } else {
        Role::Reviewer
    };

    let user = User::new(&username, &password, role);
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
        Choice::ListEstablishmentReviews => list_establishment_reviews(),
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

    if let Role::Owner {
        ref owned_establishment,
    } = user.role
    {
        if owned_establishment == &establishment {
            bail!("vous ne pouvez pas ajouter d'avis sur votre propre établissement");
        }
    }

    let comment = Text::new("Entrez votre commentaire : ")
        .with_validator(|input| is_text_length_valid(input, REVIEW_MIN_SIZE, REVIEW_MAX_SIZE))
        .prompt()?;
    let grade = CustomType::new("Entrez votre note : ")
        .with_validator(|input| is_number_in_range(input, REVIEW_MIN_GRADE, REVIEW_MAX_GRADE))
        .prompt()?;
    let review = Review::new(&establishment, &user.name, &comment, grade);

    review.save()?;

    Ok(ShouldContinue::Yes)
}

fn list_establishment_reviews() -> ShouldContinue {
    let establishment = Text::new("Entrez le nom de l'établissement : ")
        .prompt()
        .unwrap();

    //FIXME: Owner should only read their review => casbin
    //FIXME: Reviewers should only read their review => casbin
    for review in Review::of(&establishment) {
        /*
        if(e.enforce(user, review.reviewer, "read")) {
            println!("{}, review")
         }
        */
        println!("{}", review);
    }

    ShouldContinue::Yes
}

fn delete_review(_user: &User) -> anyhow::Result<ShouldContinue> {
    let establishment = Text::new("Entrez le nom de l'établissement : ").prompt()?;

    //FIXME: C'est nimp lol. It should check role, not ask for it => casbin
    let is_admin = Confirm::new("Êtes-vous administrateur ?")
        .with_default(true)
        .prompt()?;

    if !is_admin {
        bail!("vous n'êtes pas administrateur")
    }

    let name = Text::new("Entrez le nom de l'auteur de l'avis : ").prompt()?;
    let review = Review::get(&name, &establishment).ok_or(anyhow!("avis manquant"))?;

    review.delete();

    Ok(ShouldContinue::Yes)
}
