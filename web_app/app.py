"""
Application Flask - CertiScan 2D.
Principes de sécurité appliqués :
- Aucune session ni cookie ne stocke de données du document ou du rapport.
- Le fichier uploadé est écrit dans un répertoire temporaire dédié, pré-scellé
  avec des droits restrictifs (0o600), jamais renommé de façon prévisible, 
  et supprimé en `finally` quoi qu'il arrive (succès, échec, exception).
- Les fichiers HEIC/HEIF (flux iPhone) sont convertis de façon éphémère en JPEG 
  directement depuis la mémoire pour être compatibles avec la vision par ordinateur.
- Le contenu binaire est audité par 'Magic Bytes' (signatures de fichiers) dès 
  la réception pour bloquer le contournement d'extensions.
- Le rapport d'analyse vit uniquement en mémoire serveur pendant la requête.
  Pour permettre le téléchargement du PDF sans re-uploader le document, le
  rapport (métadonnées uniquement, jamais le fichier original) est renvoyé
  au client dans un champ de formulaire caché (POST), pas en session serveur.
- Un rafraîchissement de page ou la fermeture du navigateur fait perdre
  tout résultat affiché : il n'y a aucune persistance côté serveur.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import uuid
from pathlib import Path
import filetype
from PIL import Image
import pillow_heif
from flask import Flask, render_template, request, send_file, abort, Response
from certiscan2d.orchestrateur import verifier_document, RapportVerification, EtapeResultat
import certificate as certificate

# Initialisation du support du format HEIC pour Pillow
pillow_heif.register_heif_opener()

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration sécurité
MAX_CONTENT_LENGTH = 20 * 1024 * 1024  # 20 Mo, aligné sur extractor.MAX_FILE_SIZE_MB
EXTENSIONS_AUTORISEES = {".pdf", ".jpg", ".jpeg", ".png", ".tiff", ".bmp", ".heic", ".heif"}
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
# Le contenu du document ne doit jamais être mis en cache par le navigateur
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
# Répertoire dédié aux fichiers temporaires d'analyse - séparé de /tmp système
TEMP_DIR = Path(tempfile.gettempdir()) / "certiscan2d_uploads"
TEMP_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)


def _verifier_type_reel(chemin: Path, extension_declaree: str) -> bool:
    """
    Vérifie les 'Magic Bytes' du fichier pour s'assurer que le contenu
    réel correspond à l'extension déclarée par l'utilisateur (ou générée après conversion).
    Garantit l'intégrité face aux tentatives d'injection et de contournement.
    """
    kind = filetype.guess(str(chemin))
    
    # Cas de repli : filetype peut échouer sur certaines structures BMP anciennes/brutes
    if kind is None:
        return extension_declaree == ".bmp"
        
    mimetypes_attendus = {
        ".pdf": "application/pdf",
        ".jpg": "image/jpeg", 
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".tiff": "image/tiff",
        ".bmp": "image/bmp",
    }
    
    return kind.mime == mimetypes_attendus.get(extension_declaree)


@app.after_request
def ajouter_en_tetes_securite(response: Response) -> Response:
    """En-têtes de sécurité applicables à toutes les réponses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    # Aucune donnée sensible ne doit être mise en cache par un proxy ou le navigateur
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    return response


# Routes principales
@app.route("/", methods=["GET"])
def accueil():
    """Page d'accueil avec le formulaire d'upload."""
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/verifier", methods=["POST"])
def verifier():
    """
    Reçoit le fichier uploadé, effectue la conversion éphémère si le format est HEIC,
    valide sa signature binaire, lance la chaîne de vérification, et affiche le résultat.
    Le fichier est systématiquement supprimé après traitement, quel que soit le résultat.
    """
    fichier = request.files.get("document")

    if fichier is None or fichier.filename == "":
        return render_template("index.html", erreur="Aucun fichier n'a été sélectionné. Merci de choisir un document à analyser.",), 400

    extension = Path(fichier.filename).suffix.lower()
    if extension not in EXTENSIONS_AUTORISEES:
        return render_template(
            "index.html",
            erreur=f"Format de fichier non supporté ({extension or 'inconnu'}). "
                   f"Formats acceptés : PDF, JPG, PNG, TIFF, BMP, HEIC."), 400

    # Routage du format : si le document est un HEIC d'iPhone, on prépare sa conversion JPEG
    est_heic = extension in {".heic", ".heif"}
    extension_finale = ".jpg" if est_heic else extension

    # Nom de fichier temporaire imprévisible - jamais le nom d'origine sur le stockage
    nom_temp = f"{uuid.uuid4().hex}{extension_finale}"
    chemin_temp = TEMP_DIR / nom_temp

    try:
        # Résolution de la Race Condition : pré-création du descripteur avec droits stricts (0o600)
        chemin_temp.touch(mode=0o600)

        if est_heic:
            logger.info("Format d'image Apple HEIC/HEIF détecté — Démarrage de la conversion JPEG à la volée...")
            # Lecture du flux binaire directement depuis la mémoire vive
            image_heic = Image.open(fichier.stream)
            # Écriture forcée en JPEG dans notre fichier temporaire pré-scellé
            image_heic.save(str(chemin_temp), "JPEG")
        else:
            # Sauvegarde standard pour les autres types de documents
            fichier.save(str(chemin_temp))

        logger.info(f"Fichier temporaire écrit de façon sécurisée : {nom_temp}")

        # Audit de conformité binaire (Magic Bytes) sur le fichier finalisé
        if not _verifier_type_reel(chemin_temp, extension_finale):
            logger.warning(f"[ALERTE SÉCURITÉ] Discordance des Magic Bytes détectée pour le fichier temporaire {nom_temp}")
            return render_template(
                "index.html",
                erreur="Le contenu réel du fichier ne correspond pas à l'extension déclarée. Analyse refusée par mesure de sécurité."
            ), 400

        logger.info(f"Analyse démarrée — validation binaire OK pour {nom_temp}")

        # Traitement via l'orchestrateur (on conserve le nom d'origine pour l'affichage de l'audit)
        rapport = verifier_document(str(chemin_temp), fichier.filename)

        return render_template(
            "index.html",
            rapport=rapport,
            rapport_json=json.dumps(rapport.to_dict(), ensure_ascii=False))

    except Exception as e:
        logger.exception("Erreur inattendue lors du traitement de l'upload")
        return render_template(
            "index.html",
            erreur="Une erreur technique est survenue lors de l'analyse. Veuillez réessayer.",
        ), 500

    finally:
        # Nettoyage physique irréversible de la mémoire disque (Anti-persistance)
        if chemin_temp.exists():
            try:
                chemin_temp.unlink()
                logger.info(f"Fichier temporaire supprimé du stockage : {nom_temp}")
            except OSError as e:
                logger.error(f"Échec critique de suppression du fichier temporaire {nom_temp} : {e}")


@app.route("/certificat", methods=["POST"])
def telecharger_certificat():
    """
    Génère le PDF de certificat d'analyse à la volée, à partir des données
    du rapport transmises en POST (champ caché du formulaire de résultat).
    Le PDF est streamé directement, jamais écrit sur disque.
    """
    rapport_json = request.form.get("rapport_json")
    if not rapport_json:
        abort(400, description="Données de rapport manquantes.")

    try:
        rapport_dict = json.loads(rapport_json)
    except json.JSONDecodeError:
        abort(400, description="Données de rapport invalides.")

    try:
        pdf_buffer = certificate.generer_certificat_pdf(rapport_dict)
    except Exception:
        logger.exception("Erreur lors de la génération du certificat PDF")
        abort(500, description="Impossible de générer le certificat PDF.")

    nom_fichier = f"certificat_certiscan2d_{rapport_dict.get('type_document', 'document')}.pdf"

    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=nom_fichier)


# Gestion des erreurs HTTP
@app.errorhandler(413)
def fichier_trop_volumineux(e):
    return render_template("index.html", erreur="Le fichier dépasse la taille maximale autorisée (20 Mo)."), 413


@app.errorhandler(404)
def page_non_trouvee(e):
    return render_template("index.html", erreur=None), 404


@app.errorhandler(500)
def erreur_serveur(e):
    logger.exception("Erreur serveur non gérée")
    return render_template(
        "index.html", erreur="Une erreur technique est survenue. Veuillez réessayer ultérieurement."), 500


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)