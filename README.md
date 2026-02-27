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
- **Base de données comptes** : la base de Vaelith contient les comptes de tous les utilisateurs inscrits (`users`).
- **Compte admin par défaut** : `25ln4op81@gmail.com` (modifiable).

- **Recherche web assistée** : en mode recherche (ou si la question demande des sources web), Vaelith enrichit le prompt avec un contexte web (DuckDuckGo).
- **Moteur neuro-symbolique scripté** : Vaelith applique une logique d'intent scoring, extraction de mots-clés, mémoire contextuelle et plan de réponse pour reproduire un comportement type LLM sans provider externe.
- **Apprentissage par feedback utilisateur** : chaque réponse peut être notée (👍/👎) et Vaelith ajuste ses signaux de préférence sur les réponses suivantes.

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
- `POST /api/feedback` : noter une réponse (`score`: 1 ou -1)
- `GET /api/health` : santé API

## Sécurité demandée

- Tous les comptes non-admin sont bloqués si le prompt tente d'obtenir de l'aide pour tuer/blesser quelqu'un, y compris en roleplay.
- Le compte admin n'est pas filtré (comme demandé).

## Netlify (option la plus simple)

Le repo est maintenant compatible Netlify avec une **Function** (`netlify/functions/api.js`) + un routage `/api/*` via `netlify.toml`.

### Déploiement pas-à-pas (débutant)

1. Pousse le repo sur GitHub.
2. Sur Netlify: **Add new project** → **Import from Git**.
3. Dans les settings build:
   - Publish directory: `public`
   - Functions directory: `netlify/functions`
4. Variables d'environnement Netlify (Site configuration → Environment variables):
   - `ADMIN_EMAIL`
   - `ADMIN_USERNAME`
   - `ADMIN_PASSWORD`
5. Deploy.
6. Ouvre l'URL **racine** du site (ex: `https://ton-site.netlify.app/`) et **pas** `/public/`.

### Important (MVP)

La fonction utilise un stockage fichier temporaire (`/tmp`) compatible démo, mais non durable long terme. Pour la production, branche une vraie base (Supabase/Neon/etc.).

## Dépannage connexion admin

### Erreur: `Unexpected token '<', "<!DOCTYPE ..." is not valid JSON`

Cette erreur signifie que le front attend du JSON sur `/api/*`, mais reçoit une page HTML.

Ca arrive en général si:
- tu ouvres la mauvaise URL (`.../public/` au lieu de la racine),
- ou les redirects/fonctions Netlify ne sont pas actifs,
- ou une ancienne config de redirect envoie un mauvais chemin API (ca produit `Route introuvable`),
- ou le backend local n'est pas démarré.

Correctif:
- Netlify: ouvre l'URL racine du site.
- Local: `npm start`, puis `http://localhost:3000`.

Si tu vois `Route introuvable` sur Netlify, redeploie après pull de cette version (routing `/api/*` corrigé).

## Licence

Apache License 2.0.
