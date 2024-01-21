# SLH Labo 3 - Bastian Chollet

## Liste des erreur et leurs améliorations

### Authentification

| Erreur identifiée                           | Amélioration apportée                                                                                        |
|---------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| Les mot de passes sont en clair dans la DB  | Hashage des mots de passe avec Argon2.                                                                       |
|                                             | Hashage d'un mot de passe par défaut en cas d'utilisateur non trouvé en DB. Protège contre les timing attack |
| Aucune règle sur le force d'un mot de passe | Utilisation de la lib zxcvbn, et obligation d'un mot de passe de 8 caractères au minimum.                    |

### Contrôle d'accès

| Erreur identifiée                                                                                                | Amélioration apportée                                                                                                                                                                                                                                                                              |
|------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Un Owner et un Reviewer peuvent lire les avis de tout le monde via "Avis d'un établissement"                     | Utilisation de Casbin avec règle limitant l'accès selon la consigne. Un reviewer ne lira que ses reviews, alors qu'un owner pourra lire toutes les reviews de son établissement et seulement les siennes pour les autres établissements. Un Admin pourra lire toutes les reviews sans restriction. |
| Tous les rôles peuvent supprimer une review pour autant qu'ils disent "oui" à la question "Êtes-vous un admin ?" | Suppression de la question. Casbin se charge de checker le rôle de l'utilisateur et rejette sa demande s'il n'est pas Admin                                                                                                                                                                        |
| Un Owner peut review son propre restaurant                                                                       | Ajout d'une règle Casbin interdisant cette manoeuvre.                                                                                                                                                                                                                                              |

### Gestion des erreurs

| Erreur identifiée                                                                                                   | Amélioration apportée                                                                                                                                                           |
|---------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Panic lors d'un login où l'utilisateur entré n'existe pas                                                           | Suppression de l'appel à la méthode `.expect()` et remplacement de la logique pour afficher simplement un message si l'utilisateur n'existe pas ou si son mot de passe est faut |
| Panic lors des actions "Ajouter un avis" et "Supprimer un avis" (car `.unwrap()` sur un `Err` retourné par `bail!`) | Utilisation de `.unwrap_or_else()` avec un lambda affichant l'erreur remontée.                                                                                                  |

### Validation d'input

| Erreur identifiée                                                   | Amélioration apportée                                                                                                                             |
|---------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| Les noms des établissements et des utilisateurs ne sont pas validés | Ajout d'une limite de taille (entre 1 et 64 caractères), et d'une regex limitant les caractères à l'alphanumérique et aux accent latins           |
| Les reviews ne sont pas validées                                    | Ajout d'une limite de taille (entre 1 et 650 caractères)                                                                                          |
| Les mots de passes ne sont pas validés                              | Ajout d'une limite de taille (entre 8 et 64 caractères) avec utilisation de la lib zxcvbn pour tester la force du mot de passe avec un score de 2 |
| Les notes des review ne sont pas validées                           | Ajout d'une range de note selon la consigne (entre 1 et 5 compris).                                                                               |
