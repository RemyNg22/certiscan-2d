import logging
import re
import unicodedata
from typing import Dict, Any, Optional
import certiscan2d.models as mod

logger = logging.getLogger(__name__)


# Normalisation
MOIS_MAPPING = {
    "janvier": "01", "fevrier": "02", "mars": "03", "avril": "04",
    "mai": "05", "juin": "06", "juillet": "07", "aout": "08",
    "septembre": "09", "octobre": "10", "novembre": "11", "decembre": "12",
}


def normalize_text(s: str) -> str:
    """
    Normalise une chaîne pour effacer les artefacts OCR :
    minuscule, suppression accents, mois en lettres vers chiffres,
    ponctuation => espace, espaces multiples compressés.
    """
    if not s:
        return ""

    s = s.lower()
    s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))

    for mois_lettres, mois_chiffres in MOIS_MAPPING.items():
        if mois_lettres in s:
            s = s.replace(mois_lettres, mois_chiffres)

    s = re.sub(r"[.,\/#!$%\^&\*;:{}=\-_`~()\[\]?|§\"']", " ", s)
    return " ".join(s.split())


def _digits_only(s: str) -> str:
    return "".join(re.findall(r"\d+", s or ""))


"""
Champs à vérifier par type de document, seuls les champs réellement imprimés en clair sur le document méritent 
d'être vérifiés. Les champs purement techniques (cert_id, dates de signature...) sont déjà couverts par 
la vérification cryptographique.
"""
CHAMPS_A_VERIFIER = {
    # Justificatifs de domicile
    mod.JustificatifDomicile: ["nom", "prenom", "adresse_voie", "code_postal"],
    mod.FactureDomicile: ["nom", "prenom", "adresse_voie", "code_postal"],
    mod.AvisTaxeHabitation: ["nom", "prenom", "adresse_voie", "code_postal"],

    # Documents bancaires
    mod.RIB: ["qualite_nom_prenom", "code_iban", "code_bic"],
    mod.ReleveSEPAmail: ["qualite_nom_prenom"],
    mod.ReleveCompte: ["qualite_nom_prenom", "code_iban", "code_bic", "solde_compte"],

    # Fiscal
    mod.AvisImpotRevenu: ["declarant1", "annee_revenus", "numero_fiscal_d1", "revenu_fiscal_reference"],
    mod.AvisDeclaratifImpot: ["declarant1", "annee_revenus", "revenu_fiscal_reference"],
    mod.AvisDeclaratifImpotV2: ["declarant1", "annee_revenus", "impot_revenu_net", "retenue_source", "revenu_fiscal_reference"],
    mod.AvisDeclaratifImpotV3: ["declarant1", "annee_revenus", "impot_revenu_net", "retenue_source", "revenu_fiscal_reference"],
    mod.AvisImpotRevenuV2: ["declarant1", "annee_revenus", "impot_revenu_net", "retenue_source", "revenu_fiscal_reference"],
    mod.DeclarationDons: ["nom_donataire", "nom_donateur", "montant_don"],
    mod.CessionDroitsSociaux: ["nom_cessionnaire", "nom_cedant", "montant_cession"],
    mod.Attestation2041ASK: ["nom_prenom_declarant", "commune_declarant"],

    # Activité professionnelle
    mod.BulletinSalaire: ["nom", "salaire_net_imposable", "cumul_salaire_net", "siret_employeur"],
    mod.ContratTravail: ["nom_employe", "salaire_brut", "siret_employeur"],
    mod.AutorisationTravail: ["nom_employe", "prenom_employe"],
    mod.AutorisationTravailAES: ["nom_employe", "denomination_sociale"],
    mod.AttestationActiviteProfessionnelle: ["nom_salarie", "prenom_salarie"],

    # Identité
    mod.TitreIdentite: ["nom_patronymique", "liste_prenoms", "numero_piece"],
    mod.DocumentEtranger: ["nom_patronymique", "liste_prenoms", "numero_piece", "date_naissance"],

    # Véhicules
    mod.CertificatQualiteAir: ["immatriculation", "marque"],
    mod.CertificatQualiteAirV2: ["immatriculation", "marque"],
    mod.CertificatCessionElectronique: ["nom_vendeur", "nom_acheteur", "immatriculation"],

    # Permis / autorisations
    mod.ArretesPermisConduire: ["nom", "prenoms", "numero_carte"],
    mod.ReleveInformationPermis: ["nom", "prenoms"],
    mod.CertificatReussitePermis: ["nom", "prenoms", "numero_carte"],
    mod.CartePompier: ["nom", "prenoms", "numero_carte"],
    mod.PermisChasser: ["nom", "prenoms"],
    mod.LicenceConducteurTrain: ["nom", "prenoms", "numero_carte"],

    # Académique
    mod.Diplome: ["nom_patronymique", "prenom", "type_diplome", "date_naissance"],
    mod.AttestationCVE: ["nom_patronymique", "liste_prenoms", "date_naissance"],

    # Médical/santé
    mod.CertificatDeces: ["nom_defunt", "commune_deces"],
    mod.CertificatDecesV2: ["nom_defunt", "commune_deces"],
    mod.CertificatPreuveVie: ["nom_patronymique", "liste_prenoms", "date_naissance"],

    # Juridique
    mod.ActeHuissier: ["identite_huissier", "intitule_acte"],

    # MRZ, pas de texte OCR comparable de façon fiable (zone technique)
}


CHAMPS_DATE = {"date_mise_recouvrement", "date_declaration", "date_naissance", "date_signature_acte"}
CHAMPS_MONTANT = {
    "revenu_fiscal_reference", "impot_revenu_net", "reste_a_payer", "retenue_source",
    "montant_don", "montant_droits", "montant_taxable", "montant_cession",
    "salaire_net_imposable", "salaire_brut", "cumul_salaire_net", "solde_compte",
}



# Vérifications unitaires
def check_field_presence(valeur_attendue: str, texte_ocr_norm: str) -> bool:
    """Inclusion textuelle, avec fallback sans espaces pour les identifiants longs."""
    norm_val = normalize_text(valeur_attendue)
    if not norm_val:
        return False
    if norm_val in texte_ocr_norm:
        return True
    return norm_val.replace(" ", "") in texte_ocr_norm.replace(" ", "")


def check_montant(valeur_attendue: str, texte_ocr: str) -> bool:
    """Compare uniquement les suites de chiffres, insensible aux séparateurs/devises."""
    digits_attendu = _digits_only(valeur_attendue)
    if not digits_attendu:
        return False
    return digits_attendu in _digits_only(texte_ocr)


def check_date_coherence(date_attendue: str, texte_ocr_norm_sans_espace: str) -> bool:
    """Tolère un écart sur le jour ; vérifie mois+année (format JJMMAAAA -> MMAAAA)."""
    cleaned = date_attendue.strip()
    mois_annee = cleaned[2:] if len(cleaned) == 8 else cleaned
    if not mois_annee:
        return False
    return mois_annee in texte_ocr_norm_sans_espace


def detect_contradiction_montant(valeur_attendue: str, texte_ocr: str) -> bool:
    """
    Une CONTRADICTION sur un montant n'est déclarée que si l'OCR a effectivement
    lu des chiffres (donc la zone n'est pas juste mal scannée) ET que ces
    chiffres ne contiennent jamais la valeur attendue.
    """
    chiffres_ocr = _digits_only(texte_ocr)
    return bool(chiffres_ocr) and _digits_only(valeur_attendue) not in chiffres_ocr


def detect_contradiction_texte(valeur_attendue: str, texte_ocr_norm: str) -> bool:
    """
    Une CONTRADICTION sur un texte (nom, IBAN...) n'est déclarée que si AUCUN
    des mots significatifs de la valeur attendue (longueur >= 3) n'apparaît
    dans l'OCR. Si même un seul mot correspond, on considère que c'est un
    problème d'OCR partiel (MISSING), pas une preuve de fraude — un seul mot
    en commun trouvé par hasard est peu probable pour des noms/identifiants.
    """
    mots = [normalize_text(m) for m in valeur_attendue.split() if len(m) >= 3]
    if not mots:
        return False
    return not any(mot in texte_ocr_norm for mot in mots)


# Cohérence globale
def check_coherence(doc_fields: mod.DocFields, texte_ocr: str) -> Dict[str, Dict[str, Any]]:
    """
    Compare les champs critiques du 2D-Doc avec le texte OCR.

    Statuts possibles par champ :
    MATCH : valeur retrouvée dans l'OCR - cohérent
    MISSING : valeur absente de l'OCR - toléré (mauvais scan, mise en page)
    CONTRADICTION : l'OCR contient une valeur différente - signal de fraude
    Seul CONTRADICTION doit faire échouer la vérification globale.
    """
    details: Dict[str, Dict[str, Any]] = {}

    classe_doc = type(doc_fields)
    champs_a_verifier = CHAMPS_A_VERIFIER.get(classe_doc)

    if champs_a_verifier is None:
        logger.warning(
            f"Aucune liste de champs critiques définie pour '{classe_doc.__name__}' — "
            f"cohérence non vérifiable, traitée comme INVALID."
        )
        return {}

    texte_ocr_norm = normalize_text(texte_ocr)
    texte_ocr_norm_sans_espace = texte_ocr_norm.replace(" ", "")

    for champ in champs_a_verifier:
        valeur_attendue = getattr(doc_fields, champ, None)

        if valeur_attendue is None:
            continue
        valeur_attendue = str(valeur_attendue).strip()
        if not valeur_attendue or valeur_attendue.lower() == "none":
            continue

        if champ in CHAMPS_DATE:
            if check_date_coherence(valeur_attendue, texte_ocr_norm_sans_espace):
                statut = "MATCH"
            else:
                statut = "MISSING"

        elif champ in CHAMPS_MONTANT:
            if check_montant(valeur_attendue, texte_ocr):
                statut = "MATCH"
            elif detect_contradiction_montant(valeur_attendue, texte_ocr):
                statut = "CONTRADICTION"
            else:
                statut = "MISSING"

        else:
            if check_field_presence(valeur_attendue, texte_ocr_norm):
                statut = "MATCH"
            elif detect_contradiction_texte(valeur_attendue, texte_ocr_norm):
                statut = "CONTRADICTION"
            else:
                statut = "MISSING"

        details[champ] = {
            "attendu": valeur_attendue,
            "statut": statut,
            "trouve": statut != "CONTRADICTION",
        }

    return details


# Détermination du statut final
def determine_status(crypto_ok: Optional[bool], coherence_details: Dict[str, Dict[str, Any]],) -> mod.VerificationStatus:
    if crypto_ok is False:
        return mod.VerificationStatus.CRYPTO_FAIL

    if not coherence_details:
        return mod.VerificationStatus.INVALID

    a_une_contradiction = any(v["statut"] == "CONTRADICTION" for v in coherence_details.values())

    if a_une_contradiction:
        return mod.VerificationStatus.SUSPICIOUS

    if crypto_ok:
        return mod.VerificationStatus.VALID

    return mod.VerificationStatus.INVALID


# Orchestration
def orchestrer_verification(
    doc_fields: Optional[mod.DocFields],
    texte_ocr: Optional[str],
    crypto_ok: Optional[bool]) -> mod.VerificationResult:
    """
    Point d'entrée principal : combine parsing, OCR et résultat crypto
    pour produire le VerificationResult final.
    """
    if not doc_fields:
        return mod.VerificationResult(
            statut=mod.VerificationStatus.INVALID,
            message="Le document n'a pas pu être parsé (2D-Doc absent ou illisible).",
            extraction_ok=False,
            crypto_ok=crypto_ok,
            coherence_ok=False,
        )

    if not texte_ocr:
        # Le 2D-Doc est parsé mais aucun texte OCR n'est disponible.
        # On ne peut pas vérifier la cohérence, mais la crypto reste valide.
        statut = mod.VerificationStatus.CRYPTO_FAIL if crypto_ok is False else mod.VerificationStatus.INVALID
        return mod.VerificationResult(
            statut=statut,
            message="Texte OCR indisponible — cohérence non vérifiable.",
            extraction_ok=True,
            crypto_ok=crypto_ok,
            coherence_ok=None,
            champs=doc_fields,
        )

    details_coherence = check_coherence(doc_fields, texte_ocr)
    coherence_globale = (
        all(v["trouve"] for v in details_coherence.values())
        if details_coherence else None
    )

    statut_final = determine_status(crypto_ok, details_coherence)

    if statut_final == mod.VerificationStatus.VALID:
        msg = f"Document de type '{type(doc_fields).__name__}' cohérent et signature authentique."
    elif statut_final == mod.VerificationStatus.CRYPTO_FAIL:
        msg = "Signature numérique invalide — le document a pu être altéré ou n'est pas authentique."
    elif statut_final == mod.VerificationStatus.SUSPICIOUS:
        champs_en_faute = [k for k, v in details_coherence.items() if v["statut"] == "CONTRADICTION"]
        msg = f"Incohérence détectée entre le 2D-Doc et le texte visible : {', '.join(champs_en_faute)}."
    else:
        msg = "Type de document non reconnu ou cohérence non vérifiable."

    return mod.VerificationResult(
        statut=statut_final,
        message=msg,
        extraction_ok=True,
        crypto_ok=crypto_ok,
        coherence_ok=coherence_globale,
        champs=doc_fields,
        details=details_coherence)