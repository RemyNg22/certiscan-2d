# CertiScan 2D

## À propos du projet

**CertiScan 2D** est une solution de type PoC (Proof of Concept) conçue en Python/Flask pour répondre aux enjeux de la **Gouvernance, du Risque et de la Conformité (GRC)**, et plus particulièrement à la **lutte contre la fraude documentaire**.

L'application vérifie l'intégrité et la cohérence des documents officiels sécurisés par un code **2D-Doc**, standard français développé par l'ANTS (Agence Nationale des Titres Sécurisés) et utilisé sur les documents administratifs courants :

- Justificatif de domicile
- Documents bancaires
- Justificatif fiscal
- Justificatif de ressources
- Justificatif d'emploi
- Justificatif d'identité
- Justificatif de véhicule
- Certificat d'immatriculation
- Justificatif permis de conduire
- Justificatif académique
- Justificatif médical et de santé
- Justificatif d'activité

---

## Fonctionnement du 2D-Doc

Le 2D-Doc est un **Data Matrix signé électroniquement** (ECDSA). Il encode les données clés du document (nom, montant, émetteur, dates) ainsi qu'une signature cryptographique. La clé privée appartient à l'organisme émetteur et les clés publiques sont distribuées librement via la **TSL (Trusted Service List)** publiée par l'ANTS.

La vérification est donc entièrement publique : aucune convention ni accréditation n'est requise pour vérifier un 2D-Doc existant.

La présente application utilise d'ailleurs les spécifications techniques des documents utilisées dans le document suivant, émis par l'Etat Français : [Spécifications Techniques des Codes à Barres 2D-Doc](https://pub.ants.gouv.fr/2D-DOC/DOCUMENTATION/04_Specifications_Techniques/FranceTitres_DCAT_2D-DOC_V1_04_Specifications_Techniques.pdf)

---

## Fonctionnalités

### Vérification complète (Web & CLI)

Il y a trois niveau de contrôle :

**Niveau 1 — Extraction**
Lecture du Data Matrix dans le PDF et décodage.

**Niveau 2 — Vérification cryptographique réelle**
Validation ECDSA via les certificats publics ANTS. Confirme que le 2D-Doc n'a pas été falsifié.

**Niveau 3 — Cohérence documentaire**
Parsing du texte PDF et comparaison avec les champs extraits du 2D-Doc (nom, montant, émetteur, date). Détecte les modifications visuelles du document (altération du texte visible sans modification du code).

Résultats possibles :

| Statut | Signification |
|:-------|:--------------|
| **VALID** | Signature cryptographique valide + données cohérentes |
| **CRYPTO_FAIL** | Signature invalide : Data Matrix falsifié ou corrompu |
| **SUSPICIOUS** | Signature valide mais incohérences dans le texte visible |
| **INVALID** | Échec structurel (format non reconnu, Data Matrix illisible) |


---

## Cas d'usage GRC

**Gouvernance**
- Standardisation et automatisation des contrôles documentaires (KYC)
- Traçabilité des vérifications
- Réduction de la dépendance aux contrôles humains manuels

**Risques**
- Détection de falsification documentaire (deux vecteurs : crypto + cohérence)
- Identification des documents sans 2D-Doc (non vérifiables)
- Réduction du risque opérationnel sur les processus d'octroi de crédit, d'ouverture de compte bancaire, d'instruction de dossiers

**Conformité**
- Contrôles reproductibles et auditables
- Support aux exigences réglementaires (LCB-FT, DSP2)
- Vérification automatisée des justificatifs dans les parcours numériques

---

## Architecture

```text
certiscan-2d/
│
├── certiscan2d/
│   ├── __init__.py
│   ├── cli.py                   # Point d'entrée CLI (Click)
│   ├── extractor.py             # PDF -> image -> Data Matrix -> Bytes bruts
│   ├── parser.py                # Bytes → structure 2D-Doc (header + champs + signature)
│   ├── crypto.py                # Vérification ECDSA via TSL ANTS (fr_2ddoc_parser)
│   ├── verifier.py              # Cohérence : champs 2D-Doc vs texte du PDF
│   ├── orchestrateur.py         # Chaîne extractor -> parser -> crypto -> verifier
│   └── models.py                # VerificationResult, DocFields
|
|
├── cache_2ddoc/
│   ├── tsl_signed.xml           # TSL émis par l'ANTS pour le téléchargement des certificats
│   └── leaf_certs               # Les différents certificats pour la vérification cryptographique
│
├── web_app/                     # Interface Flask
│   ├── static/                  # CSS / JS
│   ├── templates/               # HTML (index, résultat, générateur)
│   └── app.py                   # Routes Flask
│
|
├── doc_ants/
│   └── FranceTitres_DCAT_2D-DOC_V1_04_Specifications_Techniques.pdf # Doc technique de l'ANTS sur lequel se base le projet
│
├── certificate.py               # génération du PDF de certificat à la volée (pdf de certification doc)
│
├── pyproject.toml               # Fichier de configuration d'installation pour CLI Linux
├── requirements.txt
└── README.md
```

---

## Installation

```bash
git clone https://github.com/RemyNg22/certiscan-2d.git
cd certiscan-2d
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

Dépendances système requises (Ubuntu/Debian) :

```bash
sudo apt install libdmtx0b tesseract-ocr tesseract-ocr-fra poppler-utils
```

---

## Utilisation

### Interface Web

```bash
flask --app web_app/app.py run
# ou en production :
gunicorn web_app.app:app
```

Fonctionnalités disponibles à `http://localhost:5000` :
- Dépôt de PDF et vérification automatique (3 niveaux)
- Rapport d'analyse détaillé
- Générateur de documents sandbox

URL de production : [https://certiscan-2d.com](https://certiscan-2d.com)

### CLI

Analyser un document depuis n'importe quel emplacement :

```bash
certiscan2d -name mon_avis_imposition.pdf
```

---

## Périmètre et limites du PoC

Ce projet utilise une **vraie vérification cryptographique** des 2D-Doc via la TSL publique de l'ANTS.

Limites actuelles :
- La vérification est celle de l'intégrité du code lui-même, pas de l'identité du porteur
- La qualité de la vérification varie selon la résolution et la mise en page du PDF source

---

## Contexte GRC et bancaire

Ce projet s'inscrit dans les problématiques de contrôle documentaire rencontrées dans les parcours d'octroi de crédit immobilier (PTZ, prêts classiques), d'ouverture de comptes clients et de mises à jour de leurs données (KYC), et plus généralement dans tout processus nécessitant la vérification de justificatifs officiels.