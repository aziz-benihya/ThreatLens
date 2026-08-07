# Guide : Publier ThreatLens sur GitHub étape par étape

## Prérequis
- Git installé sur ton PC
- Un compte GitHub (https://github.com)

---

## ÉTAPE 1 — Créer un nouveau repo sur GitHub

1. Va sur https://github.com/new
2. Remplis les champs :
   - **Repository name** : `ThreatLens` (ou le nom que tu veux)
   - **Description** : `Cyber Threat Intelligence tool using local LLMs and RAG`
   - **Visibility** : `Public` ou `Private` selon ta préférence
   - ❌ NE PAS cocher "Add a README file" (on va pousser le nôtre)
3. Clique **Create repository**
4. Copie l'URL affichée, elle ressemble à :
   `https://github.com/TON-USERNAME/ThreatLens.git`

---

## ÉTAPE 2 — Préparer le projet localement

Ouvre un terminal (cmd, PowerShell, ou Git Bash) et exécute :

```bash
# 1. Aller dans le dossier du projet
cd chemin/vers/ThreatLens-myversion

# 2. Initialiser Git
git init

# 3. Ajouter tous les fichiers
git add .

# 4. Premier commit
git commit -m "feat: initial version of ThreatLens with improved UI and multi-format support"
```

---

## ÉTAPE 3 — Connecter au repo GitHub et pousser

```bash
# 5. Connecter au repo GitHub (remplace l'URL par la tienne)
git remote add origin https://github.com/TON-USERNAME/ThreatLens.git

# 6. Renommer la branche principale en "main"
git branch -M main

# 7. Pousser le code
git push -u origin main
```

> Si GitHub te demande de t'authentifier, entre ton nom d'utilisateur
> et un **Personal Access Token** (pas ton mot de passe).
> Pour créer un token : GitHub → Settings → Developer settings → Personal access tokens → Generate new token

---

## ÉTAPE 4 — Vérifier sur GitHub

Va sur `https://github.com/TON-USERNAME/ThreatLens` → tu dois voir tous tes fichiers.

---

## ÉTAPE 5 — Workflow pour les modifications futures

Chaque fois que tu modifies le projet :

```bash
# Voir les fichiers modifiés
git status

# Ajouter les changements
git add .

# Créer un commit avec un message descriptif
git commit -m "fix: amélioration de l'interface sidebar"

# Pousser sur GitHub
git push
```

---

## Structure du projet

```
ThreatLens/
├── app.py                  # Application principale Streamlit
├── document_loader.py      # Chargement des documents (PDF, TXT, DOCX, HTML)
├── models.py               # Gestion des modèles Ollama
├── requirements.txt        # Dépendances Python
├── db/                     # Base de données vectorielle ChromaDB (pré-remplie)
├── images/
│   └── logo.webp
├── reports/                # Dossier où ajouter tes propres documents
└── .gitignore
```

---

## Modifications apportées par rapport au projet original

| Fonctionnalité | Original | Ta version |
|---|---|---|
| Formats de documents | PDF uniquement | PDF, TXT, DOCX, HTML |
| Modèle LLM par défaut | `dolphin-mistral` | `llama3` |
| Interface | Simple, sans thème | Dark theme, sidebar avec stats |
| Contexte affiché | Brut | Formaté avec source et extrait |
| Paramètre nb_docs | Fixe (CLI) | Slider interactif dans la sidebar |

---

## Lancer l'application

```bash
# Créer et activer l'environnement virtuel
python -m venv env
source env/bin/activate      # Linux/Mac
.\env\Scripts\activate       # Windows

# Installer les dépendances
pip install -r requirements.txt

# Lancer
streamlit run app.py
```
