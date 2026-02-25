# Vaelith AI

MVP en **JavaScript (Node.js)** avec **UI HTML/CSS/JS** pour lancer Vaelith avec :
- authentification par compte,
- interface type chat (style sombre bleu marin),
- modes `rapide`, `normal`, `recherche`, `roleplay`, `codage`, `enseignant`,
- règle de sécurité non-contournable pour les comptes non-admin : refus d'aide pour tuer une personne,
- compte admin configurable (email/pseudo/mot de passe modifiables).

## Fonctionnalités incluses

- **Mode rapide** : réponse ciblée en ~1-2 secondes (objectif < 5 s).
- **Mode normal** : réponse structurée en ~3-4 secondes.
- **Mode recherche** : réponse plus lente orientée recherche web (~7 s ici, extensible via API).
- **Mode roleplay** : réponse roleplay cadrée.
- **Mode codage** : réponse orientée implémentation technique.
- **Mode enseignant** : réponse pédagogique type professeur avec explications de matière.
- **Comptes utilisateurs** : inscription/connexion, édition profil.
- **Compte admin par défaut** : `25ln4op81@gmail.com` (modifiable).

## Démarrage local

```bash
cp .env.example .env
npm install
npm start
```

Puis ouvrir `http://localhost:3000`.

## Variables d'environnement

```env
PORT=3000
JWT_SECRET=change-me-in-production
ADMIN_EMAIL=25ln4op81@gmail.com
ADMIN_USERNAME=Admin
ADMIN_PASSWORD=ChangeThisPassword!
```

## API principale

- `POST /api/auth/register` : création compte
- `POST /api/auth/login` : connexion
- `GET /api/me` : profil courant
- `PATCH /api/me` : changer pseudo/mot de passe
- `PATCH /api/admin/email` : changer l'email admin (token admin requis)
- `POST /api/chat` : envoi de message avec `mode`

## Sécurité demandée

- Tous les comptes non-admin sont bloqués si le prompt tente d'obtenir de l'aide pour tuer/blesser quelqu'un, y compris en roleplay.
- Le compte admin n'est pas filtré (comme demandé).

## Netlify (cible d'hébergement)

Ce dépôt est prêt pour un MVP local. Pour un déploiement Netlify production :

1. Déplacer l'API Express vers des **Netlify Functions** (ou un backend séparé).
2. Utiliser **Netlify Identity** + base de données (Supabase/Neon/Fauna) pour la gestion de comptes à grande échelle.
3. Remplacer la logique de réponse simulée par un provider LLM (OpenAI/Anthropic/etc.).
4. Brancher le mode recherche sur une API web search (Tavily/SerpAPI/Brave Search).

## Licence

Apache License 2.0.
