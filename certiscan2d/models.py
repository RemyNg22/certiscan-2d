from dataclasses import dataclass
from enum import Enum
from typing import Optional


class VerificationStatus(Enum):
    VALID = "Document valide - Données cohérentes"
    INVALID = "Échec structurel (non reconnu)"
    CRYPTO_FAIL = "Signature numérique incorrecte"
    SUSPICIOUS = "Incohérence entre données et 2D-Code"


# Champs communs pour tous les documents
@dataclass
class DocFields:
    marqueur_id : str   # marqueur d'identitfication
    version_id : str    # version du 2D-Code
    ca_id : str     # identifiant de l'autorité de certification
    certif_id : str     # identifiant du certificat
    date_emission : str     # date d'émission
    date_signature : str    # date de création de la signature
    code_identification_doc : str   # code d'identification du document
    identifiant_perimetre : Optional[str] = None # code du périmètre à partir de la v03
    pays_emetteur : Optional[str] = None  # pays émetteur du doc



# ===============
#JUSTIFICATIF DE DOMICILE

@dataclass
class JustificatifDomicile(DocFields):
    """Type 00 — Justificatif de domicile générique"""
    adresse_ligne1 : str = None # 10 - Ligne 1 adresse postale
    titre_personne : str = None # 11 - Qualité/titre
    prenom : str = None # 12
    nom : str = None # 13
    adresse_ligne2 : str = None # 20
    adresse_ligne3 : str = None # 21
    adresse_voie : str = None # 22
    adresse_ligne5 : str = None # 23
    code_postal : str = None # 24
    localite : str = None # 25
    pays : str = None # 26


@dataclass
class FactureDomicile(DocFields):
    """Type 01 — Factures (énergie, téléphonie, internet, eau)"""
    adresse_ligne1 : str  = None   # 10 - O*
    titre_personne : str  = None   # 11 - O*
    prenom : str  = None   # 12 - O*
    nom  : str  = None   # 13 - O*
    adresse_voie : str  = None   # 22 - O
    code_postal : str  = None   # 24 - O
    pays : str  = None   # 26 - O


@dataclass
class AvisTaxeHabitation(DocFields):
    """Type 02 — Avis de taxe d'habitation"""
    adresse_ligne1 : str  = None   # 10 - O*
    titre_personne : str  = None   # 11 - O*
    prenom : str  = None   # 12 - O*
    nom : str  = None   # 13 - O*
    adresse_voie : str  = None   # 22 - O
    code_postal : str  = None   # 24 - O
    localite: str  = None   # 25 - O
    pays : str  = None   # 26 - O

# ================
# Documents bancaires

@dataclass
class RIB(DocFields):
    """Type 03 — Relevé d'Identité Bancaire"""
    qualite_nom_prenom : str  = None   # 30 - O
    code_iban  : str  = None   # 31 - O
    code_bic : str  = None   # 32 - O


@dataclass
class ReleveSEPAmail(DocFields):
    """Type 05 — Relevé d'identité SEPAmail"""
    date_expiration : str  = None   # 08 - O
    qualite_nom_prenom : str  = None   # 30 - O
    qxban : str  = None   # 35 - O


@dataclass
class ReleveCompte(DocFields):
    """Type 11 — Relevé de compte"""
    qualite_nom_prenom : str  = None   # 30 - O
    code_iban : str  = None   # 31 - O
    code_bic : str  = None   # 32 - O
    date_debut : str  = None   # 36 - O
    date_fin : str  = None   # 37 - O
    solde_compte : str  = None   # 38 - O



# ================
# Justificatif fiscal

@dataclass
class AvisImpotRevenu(DocFields):
    """Type 04 — Avis d'impôt sur les revenus"""
    nombre_parts : str  = None   # 43 - O
    reference_avis : str  = None   # 44 - O
    annee_revenus : str  = None   # 45 - O
    declarant1 : str  = None   # 46 - O
    numero_fiscal_d1 : str  = None   # 47 - O
    date_mise_recouvrement : str  = None   # 4A - O


@dataclass
class FactureEtendue(DocFields):
    """Type 09 — Facture étendue"""
    adresse_ligne1: str  = None   # 10 - O*
    titre_personne : str  = None   # 11 - O*
    prenom: str  = None   # 12 - O*
    nom : str  = None   # 13 - O*
    adresse_voie : str  = None   # 22 - O
    code_postal : str  = None   # 24 - O
    pays : str  = None   # 26 - O


@dataclass
class AvisDeclaratifImpot(DocFields):
    """Type 18 — Avis de Situation Déclarative à l'Impôt sur les Revenus"""
    nombre_parts : str  = None   # 43 - O
    reference_avis : str  = None   # 44 - O
    annee_revenus : str  = None   # 45 - O
    declarant1 : str  = None   # 46 - O
    date_declaration : str  = None   # 4B - O


@dataclass
class DeclarationDons(DocFields):
    """Type 19 — Déclaration de dons"""
    date_enregistrement : str  = None   # 4C - O
    montant_don : str  = None   # 4D - O (en €)
    montant_droits : str  = None   # 4E - O (en €)
    reference_enregistrement : str  = None   # 4F - O
    nom_donataire : str  = None   # 4G - O
    nom_donateur : str  = None   # 4H - O


@dataclass
class CessionDroitsSociaux(DocFields):
    """Type 20 — Déclarations de cession de droits sociaux"""
    date_enregistrement : str  = None   # 4C - O
    montant_droits : str  = None   # 4E - O
    reference_enregistrement : str  = None   # 4F - O
    montant_cession : str  = None   # 4J - O
    nom_cessionnaire : str  = None   # 4K - O
    nom_cedant : str  = None   # 4L - O


@dataclass
class Attestation2041ASK(DocFields):
    """Type 21 — Attestation 2041-ASK"""
    nom_prenom_declarant: str  = None   # 4N - O
    adresse_declarant : str  = None   # 4O - O
    code_postal_declarant: str  = None   # 4P - O
    commune_declarant : str  = None   # 4Q - O
    sip_gestionnaire : str  = None   # 4R - O
    millesime : str  = None   # 4S - O


@dataclass
class AvisDeclaratifImpotV2(DocFields):
    """Type 24 — Avis de Situation Déclarative à l'Impôt sur les Revenus V2"""
    nombre_parts : str  = None   # 43 - O
    reference_avis : str  = None   # 44 - O
    annee_revenus : str  = None   # 45 - O
    declarant1: str  = None   # 46 - O
    date_declaration : str  = None   # 4B - O
    impot_revenu_net : str  = None   # 4V - O
    reste_a_payer : str  = None   # 4W - O
    retenue_source: str  = None   # 4X - O


# ===================
# Activités professionnelles

@dataclass
class BulletinSalaire(DocFields):
    """Type 06 — Bulletin de salaire"""
    adresse_ligne1: str = None  # 10 - O*
    titre_personne: str = None  # 11 - O*
    prenom: str = None  # 12 - O*
    nom: str = None  # 13 - O*
    siret_employeur: str = None  # 50 - O
    debut_periode: str = None  # 53 - O
    fin_periode: str = None  # 54 - O
    date_debut_contrat: str = None  # 55 - O
    salaire_net_imposable: str = None  # 58 - O
    cumul_salaire_net: str = None  # 59 - O


@dataclass
class ContratTravail(DocFields):
    """Type 10 — Contrat de travail"""
    siret_employeur: str = None  # 50 - O
    date_signature_contrat: str = None  # 57 - O
    salaire_brut: str = None  # 5A - O
    prenom_employe: str = None  # 61 - O
    nom_employe: str = None  # 62 - O


@dataclass
class AutorisationTravail(DocFields):
    """Type 15 — Attestation de décision favorable d'autorisation de travail"""
    date_debut_contrat: str = None  # 55 - O
    numero_dossier: str = None  # 5N - O
    nom_declarant: str = None  # 5Q - O
    prenom_declarant: str = None  # 5R - O
    fonction_declarant: str = None  # 5S - O
    type_contrat: str = None  # 5T - O
    prenom_employe: str = None  # 61 - O
    nom_employe: str = None  # 62 - O
    nationalite: str = None  # 67 - O
    date_naissance: str = None  # 69 - O
    lieu_naissance: str = None  # 6A - O
    date_depot_demande: str = None  # 6L - O


@dataclass
class AutorisationTravailAES(DocFields):
    """Type 25 — Autorisation de Travail AES Métier en Tension"""
    date_association: str = None  # 06 - O
    date_signature_contrat: str = None  # 57 - O
    siret_rna: str = None  # 5L - O
    denomination_sociale: str = None  # 5M - O
    fonction_declarant: str = None  # 5S - O
    type_contrat: str = None  # 5T - O
    duree_contrat: str = None  # 5U - O
    liste_prenoms: str = None  # 60 - O
    nom_employe: str = None  # 62 - O
    nationalite: str = None  # 67 - O
    date_naissance: str = None  # 69 - O
    lieu_naissance: str = None  # 6A - O
    pays_naissance: str = None  # 6C - O
    numero_etranger: str = None  # 6Q - O
    numero_piece_identite: str = None  # 66 - O


# ================
# Justificatif d'identité

@dataclass
class TitreIdentite(DocFields):
    """Type 07 — Titre d'identité"""
    liste_prenoms: str = None  # 60 - O
    nom_patronymique: str = None  # 62 - O
    type_piece: str = None  # 65 - O
    numero_piece: str = None  # 66 - O
    nationalite: str = None  # 67 - O
    genre: str = None  # 68 - O
    pays_naissance: str = None  # 6C - O


@dataclass
class MRZ(DocFields):
    """Type 08 — Machine Readable Zone"""
    mrz: str = None  # 6F - O


@dataclass
class DocumentEtranger(DocFields):
    """Type 13 — Document étranger"""
    liste_prenoms: str = None  # 60 - O
    nom_patronymique: str = None  # 62 - O
    nom_usage: str = None  # 63 - O
    nationalite: str = None  # 67 - O
    genre: str = None  # 68 - O
    date_naissance: str = None  # 69 - O
    lieu_naissance: str = None  # 6A - O
    pays_naissance: str = None  # 6C - O
    type_document_etranger: str = None  # 6J - O
    numero_demande: str = None  # 6K - O
    date_depot_demande: str = None  # 6L - O
    autorisation: str = None  # 6P - O
    numero_etranger: str = None  # 6Q - O
    adresse_ligne4: str = None  # 6U - O
    code_postal_domicile: str = None  # 6W - O
    commune_domicile: str = None  # 6X - O


# ================
# Justificatif de véhicule

@dataclass
class CertificatQualiteAir(DocFields):
    """Type A0 — Certificat de qualité de l'air (Crit'Air)"""
    pays_immatriculation: str = None  # A0 - O
    immatriculation: str = None  # A1 - O
    marque: str = None  # A2 - O
    nom_commercial: str = None  # A3 - O
    vin: str = None  # A4 - O
    categorie: str = None  # A5 - O
    carburant: str = None  # A6 - O
    taux_co2: str = None  # A7 - O
    classe_emission: str = None  # A9 - O


@dataclass
class CourrierPermisPoints(DocFields):
    """Type A1 — Courrier Permis à Points"""
    type_lettre: str = None  # AB - O
    numero_dossier: str = None  # AC - O
    liste_prenoms: str = None  # 60 - O
    nom: str = None  # 6G - O
    civilite: str = None  # 6H - O
    date_naissance: str = None  # 69 - O


@dataclass
class CarteMobiliteInclusion(DocFields):
    """Type A2 — Carte Mobilité Inclusion (CMI)"""
    numero_carte: str = None  # AH - O
    date_expiration: str = None  # AI - O


@dataclass
class MacaronVTC(DocFields):
    """Type A3 — Macaron VTC"""
    immatriculation: str = None  # A1 - O
    numero_evtc: str = None  # AJ - O
    numero_macaron: str = None  # AK - O


@dataclass
class CarteT3P(DocFields):
    """Type A5 — Carte T3P"""
    date_expiration: str = None  # AI - O
    numero_carte_vtc: str = None  # AL - O


@dataclass
class CertificatQualiteAirV2(DocFields):
    """Type A7 — Certificat de qualité de l'air V2"""
    pays_immatriculation: str = None  # A0 - O
    immatriculation: str = None  # A1 - O
    marque: str = None  # A2 - O
    vin: str = None  # A4 - O
    categorie: str = None  # A5 - O
    carburant: str = None  # A6 - O
    classe_emission: str = None  # A9 - O
    motif_surclassement: str = None  # AM - O


@dataclass
class CertificatCessionElectronique(DocFields):
    """Type A8 — Certificat de cession électronique"""
    immatriculation: str = None  # A1 - O
    vin: str = None  # A4 - O
    kilometrage: str = None  # AN - O
    nom_vendeur: str = None  # C1 - O
    prenom_vendeur: str = None  # C2 - O
    date_heure_cession: str = None  # C3 - O
    date_signature_vendeur: str = None  # C4 - O
    nom_acheteur: str = None  # C6 - O
    prenom_acheteur: str = None  # C7 - O
    adresse_acheteur: str = None  # C8 - O
    code_postal_acheteur: str = None  # C9 - O
    commune_acheteur: str = None  # CA - O
    numero_enregistrement: str = None  # CB - O
    date_enregistrement_siv: str = None  # CC - O


@dataclass
class AttestationDICEM(DocFields):
    """Type 14 — Attestation DICEM (engins de chantier)"""
    numero_identification: str = None  # AO - O
    type_engins: str = None  # AP - O
    numero_serie: str = None  # AQ - O
    marque: str = None  # A2 - O
    couleur: str = None  # AS - O
    type_proprietaire: str = None  # AT - O
    adresse_ligne4: str = None  # AW - O
    code_postal: str = None  # AY - O
    commune: str = None  # AZ - O
    liste_prenoms: str = None  # 60 - O (si personne physique)
    nom_patronymique: str = None  # 62 - O (si personne physique)
    date_naissance: str = None  # 69 - O (si personne physique)
    lieu_naissance: str = None  # 6A - O (si personne physique)


# ================
# Justificatif permis de conduire

@dataclass
class ArretesPermisConduire(DocFields):
    """Type AA — Arrêtés Permis de conduire"""
    nom: str = None  # 80 - O
    prenoms: str = None  # 81 - O
    numero_carte: str = None  # 82 - O


@dataclass
class ReleveInformationPermis(DocFields):
    """Type AB — Relevé d'Information Permis de conduire"""
    nom: str = None  # 80 - O
    prenoms: str = None  # 81 - O
    numero_licence: str = None  # 86 - O


@dataclass
class CertificatReussitePermis(DocFields):
    """Type AD — Certificat de réussite à l'Examen du Permis de Conduire"""
    nom: str = None  # 80 - O
    prenoms: str = None  # 81 - O
    numero_carte: str = None  # 82 - O


# ================
# Justificatif académique

@dataclass
class Diplome(DocFields):
    """Type B0 — Diplôme"""
    genre: str = None  # B6 - O
    date_naissance: str = None  # B7 - O
    pays_naissance: str = None  # B9 - O
    liste_prenoms: str = None  # B0 - O (interchangeable avec B1)
    prenom: str = None  # B1 - O
    nom_patronymique: str = None  # B2 - O
    niveau_diplome: str = None  # BD - O
    type_diplome: str = None  # BG - O
    domaine: str = None  # BH - O
    mention: str = None  # BI - O
    specialite: str = None  # BJ - O


@dataclass
class AttestationCVE(DocFields):
    """Type B1 — Attestation de Versement de la Contribution à la Vie Étudiante"""
    date_naissance: str = None  # B7 - O
    liste_prenoms: str = None  # B0 - O
    nom_patronymique: str = None  # B2 - O
    numero_identification: str = None  # BB - O
    numero_attestation_cve: str = None  # BK - O


# ================
# Justificatif médical/santé

@dataclass
class CertificatDeces(DocFields):
    """Type A4 — Certificat de décès"""
    date_heure_deces: str = None  # 70 - O (interchangeable avec 71)
    date_heure_constat: str = None  # 71 - O (interchangeable avec 70)
    nom_defunt: str = None  # 72 - O
    prenoms_defunt: str = None  # 73 - O
    commune_deces: str = None  # 77 - O
    code_postal_deces: str = None  # 78 - O
    obstacle_medico_legal: str = None  # 7C - O
    mise_en_biere: str = None  # 7D - O
    obstacle_conservation: str = None  # 7E - O
    recherche_cause_deces: str = None  # 7G - O
    code_nnc: str = None  # 7K - O
    identification_medecin: str = None  # 7M - O


@dataclass
class CertificatDecesV2(DocFields):
    """Type AE — Certificat de décès V2"""
    date_heure_deces: str = None  # 70 - O (interchangeable avec 71)
    date_heure_constat: str = None  # 71 - O (interchangeable avec 70)
    nom_defunt: str = None  # 72 - O
    prenoms_defunt: str = None  # 73 - O
    commune_deces: str = None  # 77 - O
    code_postal_deces: str = None  # 78 - O
    obstacle_medico_legal: str = None  # 7C - O
    mise_en_biere: str = None  # 7D - O
    obstacle_conservation: str = None  # 7E - O
    recherche_cause_deces: str = None  # 7G - O
    identification_medecin: str = None  # 7M - O
    identifiant_certificat: str = None  # 7P - O


@dataclass
class CertificatPreuveVie(DocFields):
    """Type 23 — Certificat de Preuve de Vie"""
    nom_patronymique: str = None  # 87 - O
    liste_prenoms: str = None  # 60 - O
    identifiant_assure: str = None  # 88 - O
    date_naissance: str = None  # 69 - O
    date_debut_campagne: str = None  # 8A - O
    identifiant_enquete: str = None  # 8B - O
    identifiant_certificat: str = None  # 8C - O
    date_emission_cert: str = None  # 8D - O
    indicateur_dematerialisation: str = None  # 8J - O


# ================
# Justificatif d'activité

@dataclass
class CartePompier(DocFields):
    """Type A6 — Carte Professionnelle Sapeur-Pompier"""
    nom: str = None  # 80 - O
    prenoms: str = None  # 81 - O
    numero_carte: str = None  # 82 - O
    organisme_tutelle: str = None  # 83 - O


@dataclass
class PermisChasser(DocFields):
    """Type A9 — Permis de chasser"""
    nom: str = None  # 80 - O
    prenoms: str = None  # 81 - O
    date_naissance: str = None  # 69 - O
    numero_permis: str = None  # 85 - O


@dataclass
class LicenceConducteurTrain(DocFields):
    """Type AC — Licence de conducteur de train"""
    nom: str = None  # 80 - O
    prenoms: str = None  # 81 - O
    numero_carte: str = None  # 82 - O
    numero_licence: str = None  # 86 - O


# ================
# Documents juridiques

@dataclass
class ActeHuissier(DocFields):
    """Type 12 — Acte d'huissier de justice"""
    identite_huissier: str = None  # 90 - O
    identite_destinataire: str = None  # 92 - O
    intitule_acte: str = None  # 94 - O
    date_signature_acte: str = None  # 96 - O


# ================
# MAPPING code → classe (utilisé dans parser.py)

DOC_TYPE_MAP = {
    "00": JustificatifDomicile,
    "01": FactureDomicile,
    "02": AvisTaxeHabitation,
    "03": RIB,
    "04": AvisImpotRevenu,
    "05": ReleveSEPAmail,
    "06": BulletinSalaire,
    "07": TitreIdentite,
    "08": MRZ,
    "09": FactureEtendue,
    "10": ContratTravail,
    "11": ReleveCompte,
    "12": ActeHuissier,
    "13": DocumentEtranger,
    "14": AttestationDICEM,
    "15": AutorisationTravail,
    "18": AvisDeclaratifImpot,
    "19": DeclarationDons,
    "20": CessionDroitsSociaux,
    "21": Attestation2041ASK,
    "23": CertificatPreuveVie,
    "24": AvisDeclaratifImpotV2,
    "25": AutorisationTravailAES,
    "A0": CertificatQualiteAir,
    "A1": CourrierPermisPoints,
    "A2": CarteMobiliteInclusion,
    "A3": MacaronVTC,
    "A4": CertificatDeces,
    "A5": CarteT3P,
    "A6": CartePompier,
    "A7": CertificatQualiteAirV2,
    "A8": CertificatCessionElectronique,
    "A9": PermisChasser,
    "AA": ArretesPermisConduire,
    "AB": ReleveInformationPermis,
    "AC": LicenceConducteurTrain,
    "AD": CertificatReussitePermis,
    "AE": CertificatDecesV2,
    "B0": Diplome,
    "B1": AttestationCVE,
}

# =================
# Résultat de l'analyse

@dataclass
class VerificationResult:
    statut : VerificationStatus
    message : str
    extraction_ok : Optional[bool] = None
    crypto_ok : Optional[bool] = None
    coherence_ok : Optional[bool] = None
    champs : Optional[DocFields] = None
    details : Optional[dict] = None

    