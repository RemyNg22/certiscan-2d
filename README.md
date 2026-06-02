# CertiScan 2D

## À propos du projet
**CertiScan 2D** est une solution de type PoC (Proof of Concept) conçue en Python/Flask pour répondre aux enjeux de la **Gouvernance, du Risque et de la Conformité (GRC)**, et plus particulièrement à la **lutte contre la fraude documentaire**. 

L'application permet de vérifier l'intégrité et la cohérence des documents officiels sécurisés par un code 2D, couramment utilisé sur certains documents officiels ou administratifs tels que :
- Avis d'imposition
- Bulletins de salaire
- Factures d'énergie
- Attestations administratives
- Documents d'entreprise

**Fonctionnalités clés :**
1. **Analyse de cohérence (Web & CLI) :** Extraction du texte du PDF (Parsing/OCR) et lecture du code 2D pour vérifier que les informations visibles sur le document (Nom, Montant, Émetteur) correspondent exactement aux données scellées dans le code.

Résultats possibles :
| Statut | Description |
|:--------|:------------|
| **VALID** | Les informations sont cohérentes |
| **SUSPICIOUS** | Incohérences partielles détectées |
| **INVALID** | Les données ne correspondent pas |

2. **Générateur "Sandbox" (Web) :** Création de documents et de codes 2D factices avec signature cryptographique simulée à des fins de test et de démonstration de vulnérabilités.

---

## Cas d'usage GRC
Le projet vise à illustrer plusieurs concepts :

**Gouvernance**
- Standardisation des contrôles documentaires
- Automatisation des vérifications (KYC - *Know Your Customer*)
- Amélioration de la traçabilité

**Risques**
- Détection de falsification documentaire
- Contrôle de cohérence
- Réduction du risque opérationnel

**Conformité**
- Contrôles reproductibles
- Support aux audits
- Vérification automatisée des justificatifs

---

## Installation et Utilisation
### 1. Clonage et initialisation de l'environnement
```bash
git clone [https://github.com/RemyNg22/certiscan-2d.git](https://github.com/RemyNg22/certiscan-2d.git)
cd certiscan-2d
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e
```

Vous pouvez désormais analyser un document directement depuis n'importe quel emplacement de votre terminal Linux:
```bash
certiscan2d -name mon_avis_imposition.pdf
```

### 2. Interface Web
L'application dispose d'une interface web publique permettant :

- Dépôt de PDF
- Vérification automatique
- Consultation du rapport d'analyse
- Génération de QR Codes de démonstration
- Création de documents de test

URL de production
[https://certiscan-2d.com](https://certiscan-2d.com)

---

## Architecture
```text
certiscan-2d/
│
├── certiscan2d/
│   ├── __init__.py
│   ├── cli.py              # Point d'entrée la ligne de commande
│   ├── decoder.py          # Lecture du PDF et extraction/décodage du 2D-Doc
│   ├── generator.py        # Génération d'un 2D-Doc factice (signature factice)
│   └── verifier.py         # Comparaison texte PDF vs données 2D-Doc
│
├── web_app/                # L'interface Flask
│   ├── static/             # CSS / JS
│   ├── templates/          # HTML (Index, Résultat, Générateur)
│   └── app.py              # Routes Flask (qui appellent le package certiscan2d)
│
├── setup.py                # Pour permettre le "pip install -e ." et la commande CLI
├── requirements.txt
└── README.md
```

---

## Technologies utilisées

- **Backend** : Python
- **Web** : Flask / Gunicorn
- **PDF Processing** : pdfplumber / pypdf
- **Scanner 2D Code** : pylibdmtx / OpenCV
- **CLI Engine** : Click
- **Sécurité** : cryptography