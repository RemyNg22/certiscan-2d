"""
Orchestrateur CertiScan 2D.
Point d'entrée unique appelé par cli.py et app.py (Flask). Chaîne les quatre
étapes de vérification d'un document : extraction du Data Matrix, parsing
2D-Doc, vérification cryptographique, et contrôle de cohérence OCR.

Aucune donnée n'est persistée sur disque par cet orchestrateur : le fichier
reçu est traité depuis un chemin temporaire fourni par l'appelant, qui reste
responsable de sa suppression.
"""

from __future__ import annotations
import logging
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import certiscan2d.models as mod
import certiscan2d.extractor as extractor
import certiscan2d.parser as parser
import certiscan2d.crypto as crypto
import certiscan2d.verifier as verifier
logger = logging.getLogger(__name__)


# Résultat structuré, utilisé par CLI, Flask et génération PDF
@dataclass
class EtapeResultat:
    """Résultat d'une étape individuelle de la chaîne, pour affichage pas-à-pas."""
    nom: str # "Extraction", "Parsing", "Cryptographie", "Cohérence"
    statut: str # "ok", "echec", "ignore"
    message: str = ""
    duree_ms: Optional[float] = None


@dataclass
class RapportVerification:
    """
    Résultat complet d'une vérification, suffisant pour :
    - l'affichage web
    - la génération du certificat PDF
    - l'affichage CLI
    """
    # Identité du document
    nom_fichier_origine: str
    type_document: str # nom de la classe, ex "AvisImpotRevenuV2"
    type_document_libelle: str # libellé humain, ex "Avis d'impôt sur les revenus"

    # Statut global
    statut: str # valeur de VerificationStatus
    statut_libelle: str # message humain associé
    message_principal: str

    # Horodatage
    horodatage: str

    # Détail par étape (pour affichage pédagogique "pro")
    etapes: List[EtapeResultat] = field(default_factory=list)

    # Détails techniques
    extraction_ok: Optional[bool] = None
    crypto_ok: Optional[bool] = None
    coherence_ok: Optional[bool] = None

    # Infos crypto à afficher (partiellement masquées pour ne pas exposer toute la donnée technique, mais suffisant pour prouver la vérification)
    autorite_certification: Optional[str] = None # ca_id, ex "FR06"
    identifiant_certificat: Optional[str] = None # cert_id, ex "FPE6"
    signature_apercu: Optional[str] = None # premiers/derniers caractères

    # Champs vérifiés (issus de CHAMPS_A_VERIFIER) avec leur statut individuel
    champs_verifies: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Erreur technique éventuelle (pour debug, jamais affichée telle quelle à l'utilisateur final)
    erreur_technique: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


# Libellés humains pour les types de documents
LIBELLES_DOCUMENTS = {
    mod.JustificatifDomicile: "Justificatif de domicile",
    mod.FactureDomicile: "Facture (justificatif de domicile)",
    mod.AvisTaxeHabitation: "Avis de taxe d'habitation",
    mod.RIB: "Relevé d'Identité Bancaire",
    mod.ReleveSEPAmail: "Relevé d'identité SEPAmail",
    mod.ReleveCompte: "Relevé de compte bancaire",
    mod.AvisImpotRevenu: "Avis d'impôt sur les revenus",
    mod.FactureEtendue: "Facture étendue",
    mod.AvisDeclaratifImpot: "Avis de Situation Déclarative à l'Impôt sur les Revenus",
    mod.DeclarationDons: "Déclaration de dons",
    mod.CessionDroitsSociaux: "Déclaration de cession de droits sociaux",
    mod.Attestation2041ASK: "Attestation 2041-ASK",
    mod.AvisDeclaratifImpotV2: "Avis de Situation Déclarative à l'Impôt sur les Revenus (V2)",
    mod.AvisDeclaratifImpotV3: "Avis de Situation Déclarative à l'Impôt sur les Revenus (V3)",
    mod.AvisImpotRevenuV2: "Avis d'impôt sur les revenus (V2)",
    mod.BulletinSalaire: "Bulletin de salaire",
    mod.ContratTravail: "Contrat de travail",
    mod.AutorisationTravail: "Autorisation de travail",
    mod.AutorisationTravailAES: "Autorisation de Travail AES",
    mod.AttestationActiviteProfessionnelle: "Attestation d'Activité Professionnelle",
    mod.TitreIdentite: "Titre d'identité",
    mod.MRZ: "Zone de Lecture Automatique (MRZ)",
    mod.DocumentEtranger: "Document étranger",
    mod.CertificatQualiteAir: "Certificat de qualité de l'air (Crit'Air)",
    mod.CourrierPermisPoints: "Courrier Permis à Points",
    mod.CarteMobiliteInclusion: "Carte Mobilité Inclusion",
    mod.MacaronVTC: "Macaron VTC",
    mod.CarteT3P: "Carte T3P",
    mod.CertificatQualiteAirV2: "Certificat de qualité de l'air (V2)",
    mod.CertificatCessionElectronique: "Certificat de cession électronique",
    mod.AttestationDICEM: "Attestation DICEM",
    mod.ArretesPermisConduire: "Arrêté Permis de conduire",
    mod.ReleveInformationPermis: "Relevé d'Information Permis de conduire",
    mod.CertificatReussitePermis: "Certificat de réussite à l'Examen du Permis de Conduire",
    mod.Diplome: "Diplôme",
    mod.AttestationCVE: "Attestation de Versement de la CVE",
    mod.CertificatDeces: "Certificat de décès",
    mod.CertificatDecesV2: "Certificat de décès (V2)",
    mod.CertificatPreuveVie: "Certificat de Preuve de Vie",
    mod.CartePompier: "Carte Professionnelle Sapeur-Pompier",
    mod.PermisChasser: "Permis de chasser",
    mod.LicenceConducteurTrain: "Licence de conducteur de train",
    mod.ActeHuissier: "Acte d'huissier de justice",
    mod.DocFields: "Document 2D-Doc (type non reconnu)"}


def _libelle_document(doc_fields: mod.DocFields) -> str:
    return LIBELLES_DOCUMENTS.get(type(doc_fields), type(doc_fields).__name__)


def _apercu_signature(signature_brute: Optional[str]) -> Optional[str]:
    """
    Retourne un aperçu de la signature pour affichage, assez pour
    prouver qu'une vérification cryptographique a eu lieu, sans exposer la
    signature complète inutilement.
    """
    if not signature_brute:
        return None
    sig = signature_brute.strip()
    if len(sig) <= 16:
        return sig
    return f"{sig[:8]}…{sig[-8:]} ({len(sig)} caractères)"


# Construction du rapport en cas d'échec précoce
def _rapport_echec(
    nom_fichier: str,
    etape_echouee: str,
    message: str,
    etapes: List[EtapeResultat],
    erreur_technique: Optional[str] = None):

    return RapportVerification(
        nom_fichier_origine=nom_fichier,
        type_document="Inconnu",
        type_document_libelle="Document non identifié",
        statut=mod.VerificationStatus.INVALID.name,
        statut_libelle=mod.VerificationStatus.INVALID.value,
        message_principal=message,
        horodatage=datetime.now(timezone.utc).strftime("%d/%m/%Y"),
        etapes=etapes,
        extraction_ok=(etape_echouee != "extraction"),
        erreur_technique=erreur_technique)


# Point d'entrée principal
def verifier_document(file_path: str, nom_fichier_origine: str) -> RapportVerification:
    """
    Exécute la chaîne complète de vérification sur un fichier (PDF ou image).

    Paramètres :
    file_path : chemin vers le fichier à analyser (temporaire, géré par l'appelant, non supprimé ici)
    nom_fichier_origine : nom original du fichier, pour affichage uniquement

    Retourne un RapportVerification complet
    """
    etapes: List[EtapeResultat] = []

    # Étape 1 : Extraction du Data Matrix
    t0 = time.monotonic()
    try:
        resultat_extraction = extractor.extract_document(file_path)
        duree = (time.monotonic() - t0) * 1000
        etapes.append(EtapeResultat(
            nom="Extraction du code 2D-Doc",
            statut="ok",
            message=f"{len(resultat_extraction.get('pages', []))} page(s) analysée(s)",
            duree_ms=round(duree, 1)))
        
    except extractor.ExtractionError as e:
        duree = (time.monotonic() - t0) * 1000
        etapes.append(EtapeResultat(
            nom="Extraction du code 2D-Doc et/ou texte documentaire",
            statut="echec",
            message=str(e),
            duree_ms=round(duree, 1)))
        
        return _rapport_echec(
            nom_fichier_origine, "extraction",
            "Aucun code 2D-Doc valide n'a pu être extrait de ce document.",
            etapes, erreur_technique=str(e))
    
    except Exception as e:
        logger.exception("Erreur inattendue lors de l'extraction")
        etapes.append(EtapeResultat(
            nom="Extraction du code 2D-Doc", statut="echec",
            message="Erreur technique inattendue"))
        
        return _rapport_echec(
            nom_fichier_origine, "extraction",
            "Une erreur technique est survenue lors de la lecture du fichier.",
            etapes, erreur_technique=str(e))

    # Étape 2 : Parsing du 2D-Doc
    t0 = time.monotonic()
    try:
        doc_fields = parser.parse_extractor_output(resultat_extraction)
        if doc_fields is None:
            duree = (time.monotonic() - t0) * 1000
            etapes.append(EtapeResultat(
                nom="Analyse du 2D-Doc", statut="echec",
                message="Structure non reconnue",
                duree_ms=round(duree, 1)))
            
            return _rapport_echec(
                nom_fichier_origine, "parsing",
                "Le code 2D-Doc détecté n'a pas une structure reconnue.",
                etapes)
        
        duree = (time.monotonic() - t0) * 1000
        etapes.append(EtapeResultat(
            nom="Analyse du 2D-Doc", statut="ok",
            message=f"Type identifié : {_libelle_document(doc_fields)}",
            duree_ms=round(duree, 1)))
        
    except parser.ParseError as e:
        duree = (time.monotonic() - t0) * 1000
        etapes.append(EtapeResultat(
            nom="Analyse du 2D-Doc", statut="echec",
            message=str(e), duree_ms=round(duree, 1)))
        
        return _rapport_echec(
            nom_fichier_origine, "parsing",
            "Le code 2D-Doc n'a pas pu être interprété.",
            etapes, erreur_technique=str(e))
    
    except Exception as e:
        logger.exception("Erreur inattendue lors du parsing")
        etapes.append(EtapeResultat(nom="Analyse du 2D-Doc", statut="echec", message="Erreur technique"))
        return _rapport_echec(
            nom_fichier_origine, "parsing",
            "Une erreur technique est survenue lors de l'analyse du 2D-Doc.",
            etapes, erreur_technique=str(e))

    # Étape 3 : Vérification cryptographique
    t0 = time.monotonic()
    crypto_ok: Optional[bool] = None
    message_crypto = ""
    try:
        crypto.verify_2ddoc_signature(doc_fields)
        crypto_ok = True
        duree = (time.monotonic() - t0) * 1000
        message_crypto = "Signature authentique, émise par une autorité de certification reconnue"
        etapes.append(EtapeResultat(
            nom="Vérification cryptographique", statut="ok",
            message=message_crypto, duree_ms=round(duree, 1)))
        
    except crypto.SignatureInvalideError as e:
        crypto_ok = False
        duree = (time.monotonic() - t0) * 1000
        message_crypto = "Signature invalide — le document a pu être falsifié"
        etapes.append(EtapeResultat(
            nom="Vérification cryptographique", statut="echec",
            message=message_crypto, duree_ms=round(duree, 1)))
        
    except crypto.AcInconnueError as e:
        crypto_ok = None # ni valide ni invalide — impossible à vérifier
        duree = (time.monotonic() - t0) * 1000
        message_crypto = "Autorité de certification non reconnue — vérification impossible"
        etapes.append(EtapeResultat(
            nom="Vérification cryptographique", statut="ignore",
            message=message_crypto, duree_ms=round(duree, 1)))
    except crypto.CryptoError as e:
        crypto_ok = None
        duree = (time.monotonic() - t0) * 1000
        message_crypto = "Vérification cryptographique impossible (données insuffisantes)"
        etapes.append(EtapeResultat(
            nom="Vérification cryptographique", statut="ignore",
            message=message_crypto, duree_ms=round(duree, 1)))
        

    except Exception as e:
        logger.exception("Erreur inattendue lors de la vérification cryptographique")
        crypto_ok = None
        message_crypto = "Erreur technique lors de la vérification cryptographique"
        etapes.append(EtapeResultat(nom="Vérification cryptographique", statut="echec", message=message_crypto))

    # Étape 4 : Cohérence OCR /2D-Doc
    t0 = time.monotonic()
    texte_ocr = _extraire_texte_complet(resultat_extraction)

    try:
        rapport_verifier = verifier.orchestrer_verification(doc_fields, texte_ocr, crypto_ok)
        duree = (time.monotonic() - t0) * 1000

        if rapport_verifier.coherence_ok is True:
            msg_coherence = "Toutes les données vérifiées correspondent au texte du document"
            statut_etape = "ok"
        elif rapport_verifier.coherence_ok is False:
            msg_coherence = "Incohérence détectée entre le 2D-Doc et le texte visible"
            statut_etape = "echec"
        else:
            msg_coherence = "Cohérence non vérifiable (texte insuffisant)"
            statut_etape = "ignore"

        etapes.append(EtapeResultat(
            nom="Contrôle de cohérence", statut=statut_etape,
            message=msg_coherence, duree_ms=round(duree, 1)))
        


    except Exception as e:
        logger.exception("Erreur inattendue lors du contrôle de cohérence")
        etapes.append(EtapeResultat(nom="Contrôle de cohérence", statut="echec", message="Erreur technique"))
        rapport_verifier = mod.VerificationResult(
            statut=mod.VerificationStatus.INVALID,
            message="Erreur technique lors du contrôle de cohérence",
            extraction_ok=True, crypto_ok=crypto_ok, coherence_ok=None,
            champs=doc_fields)

    # Assemblage du rapport final
    return RapportVerification(
        nom_fichier_origine=nom_fichier_origine,
        type_document=type(doc_fields).__name__,
        type_document_libelle=_libelle_document(doc_fields),
        statut=rapport_verifier.statut.name,
        statut_libelle=rapport_verifier.statut.value,
        message_principal=rapport_verifier.message,
        horodatage=datetime.now(timezone.utc).strftime("%d/%m/%Y"),
        etapes=etapes,
        extraction_ok=True,
        crypto_ok=crypto_ok,
        coherence_ok=rapport_verifier.coherence_ok,
        autorite_certification=doc_fields.ca_id,
        identifiant_certificat=doc_fields.certif_id,
        signature_apercu=_apercu_signature(doc_fields.signature_brute),
        champs_verifies=rapport_verifier.details or {},
    )


def _extraire_texte_complet(resultat_extraction: dict) -> str:
    """Concatène le texte OCR de toutes les pages pour la vérification de cohérence."""
    textes = [p.get("text", "") for p in resultat_extraction.get("pages", []) if p.get("text")]
    return "\n".join(textes)