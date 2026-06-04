from dataclasses import dataclass
from enum import Enum
from typing import Optional

@dataclass
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
class type_00(DocFields):
    """
    Document émis spécifiquement pour servir de justificatif de domicile
    """
    pass



@dataclass
class type_01(DocFields):
    """
    - Factures de fournisseur d’énergie
    - Factures de téléphonie
    - Factures de fournisseur d’accès internet
    - Factures de fournisseur d'eau
    """
    pass



@dataclass
class type_02(DocFields):
    """
    Avis taxe d'habitation
    """
    pass


# ================
# Documents bancaires

@dataclass
class type_03(DocFields):
    """
    Relevé d'identité bancaire
    """
    pass



@dataclass
class type_05(DocFields):
    """
    Relevé d'identité SEPAmail
    """
    pass


@dataclass
class type_11(DocFields):
    """
    Relevé de compte
    """
    pass


# ================
# Justificatif fiscal

@dataclass
class type_09(DocFields):
    """
    Facture étendue
    """
    pass


@dataclass
class type_19(DocFields):
    """
    Déclaration de dons
    """
    pass


@dataclass
class type_20(DocFields):
    """
    Déclarations de cession de droits sociaux
    """
    pass


@dataclass
class type_21(DocFields):
    """
    Attestation 2041-ASK
    """
    pass


# ================
# Justificatif de ressources

@dataclass
class type_04(DocFields):
    """
    Avis d’impôt sur les revenus
    """
    pass

@dataclass
class type_06(DocFields):
    """
    Bulletin de salaire
    """
    pass

@dataclass
class type_18(DocFields):
    """
    Avis de Situation Déclarative à l'Impôt sur les Revenus
    """
    pass

@dataclass
class type_24(DocFields):
    """
    Avis de Situation Déclarative à l'Impôt sur les Revenus (V2)
    """
    pass


# ================
# Justificatif d'emploi

@dataclass
class type_10(DocFields):
    """
    Contrat de travail
    """
    pass

@dataclass
class type_15(DocFields):
    """
    Attestation de décision favorable d'une demande d'autorisation de travail
    """
    pass

@dataclass
class type_25(DocFields):
    """
    Autorisation de Travail – AES Métier en Tension

    """
    pass



# ================
# Justificatif d'identité

@dataclass
class type_07(DocFields):
    """
    Titre d’identité
    """
    pass

@dataclass
class type_08(DocFields):
    """
    MRZ
    """
    pass

@dataclass
class type_13(DocFields):
    """
    Document étranger
    """
    pass


# ================
# Justificatif de véhicule

@dataclass
class type_A0(DocFields):
    """
    Certificat de qualité de l’air
    """
    pass

@dataclass
class type_A7(DocFields):
    """
    Certificat de qualité de l’air (V2)
    """
    pass

@dataclass
class type_14(DocFields):
    """
    Attestation DICEM
    """
    pass



# ================
# Certificat d'imatriculation

@dataclass
class type_24(DocFields):
    """
    Certificat de cession électronique
    """
    pass



# ================
# Justificatif permis de conduire

@dataclass
class type_A1(DocFields):
    """
    Courrier Permis à Points
    """
    pass

@dataclass
class type_AA(DocFields):
    """
    Arrêtés Permis de conduire
    """
    pass

@dataclass
class type_AB(DocFields):
    """
    Relevé d’Information Permis de conduire
    """
    pass

@dataclass
class type_AD(DocFields):
    """
    Certificat de réussite à l'Examen du Permis de Conduire (CEPC)
    """
    pass


# ================
# Justificatif académique

@dataclass
class type_B0(DocFields):
    """
    Diplôme
    """
    pass

@dataclass
class type_B1(DocFields):
    """
    Attestation de Versement de la Contribution à la Vie Etudiante
    """
    pass



# ================
# Justificatif médical/santé

@dataclass
class type_A4(DocFields):
    """
    Certificat de décès
    """
    pass

@dataclass
class type_AE(DocFields):
    """
    Certificat de décès V2
    """
    pass


@dataclass
class type_A2(DocFields):
    """
    Carte Mobilité Inclusion (CMI)
    """
    pass


@dataclass
class type_23(DocFields):
    """
    Certificat de Preuve de Vie
    """
    pass


# ================
# Justificatif d'activité

@dataclass
class type_A3(DocFields):
    """
    Macaron VTC (Véhicule de Transport avec Chauffeur)
    """
    pass

@dataclass
class type_A5(DocFields):
    """
    Carte T3P (Transport Public Particulier de Personnes)
    """
    pass


@dataclass
class type_A6(DocFields):
    """
    Carte Professionnelle Sapeur-Pompier
    """
    pass


@dataclass
class type_A9(DocFields):
    """
    Permis de chasser
    """
    pass


@dataclass
class type_AC(DocFields):
    """
    Licence de conducteur de train
    """
    pass