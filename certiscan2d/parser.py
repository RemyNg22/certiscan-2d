import dataclasses
import logging
from typing import Dict, Any, Optional
import certiscan2d.models as mod

# Séparateurs définis dans la spec ANTS
GS = "\x1d" # Group Separator - sépare les champs de données
US = "\x1f" # Unit Separator - sépare les données de la signature
RS = "\x1e" # Information Separator Two - utilisé parfois pour tronquer ou marquer la fin

class ParseError(Exception):
    pass

# Correspondance complète identifiant ANTS -> nom d'attribut dans la dataclass (Spécifications V3.3.8)
FIELD_MAP = {
    # Données d'en-tête / Communs
    "06": "date_association", # Date de l'association entre le document et le code 2D-DOC
    "08": "date_expiration", # Date d'expiration du document
    
    # Adresses et Identités bénéficiaire / client / déclarant
    "10": "adresse_ligne1", # Ligne 1 de la norme adresse postale
    "11": "titre_personne", # Qualité de la personne bénéficiaire de la prestation
    "12": "prenom", # Prénom du bénéficiaire de la prestation
    "13": "nom", # Nom de la personne bénéficiaire
    "20": "adresse_ligne2", # Ligne 2 de la norme adresse postale
    "21": "adresse_ligne3", # Ligne 3 de la norme adresse postale
    "22": "adresse_voie", # Ligne 4 de la norme adresse postale (Numéro, type et nom de la voie)
    "23": "adresse_ligne5", # Ligne 5 de la norme adresse postale (Mention de distribution / BP)
    "24": "code_postal", # Code postal ou code cedex du point de service
    "25": "localite", # Localité de destination ou libellé cedex
    "26": "pays", # Pays de service des prestations
    
    # Secteur bancaire & SEPAmail
    "30": "qualite_nom_prenom", # Qualité Nom et Prénom (RIB, Relevés)
    "31": "code_iban", # Code IBAN
    "32": "code_bic", # Code BIC
    "35": "qxban", # Identifiant SEPAmail (QXBAN)
    "36": "date_debut", # Date de début de période
    "37": "date_fin", # Date de fin de période
    "38": "solde_compte", # Solde compte courant début de période
    
    # Justificatifs fiscaux & Impôts
    "40": "numero_fiscal", # Numéro fiscal du foyer
    "41": "revenu_fiscal_reference", # Revenu fiscal de référence
    "42": "situation_foyer", # Situation du foyer
    "43": "nombre_parts", # Nombre de parts
    "44": "reference_avis", # Référence d'avis d'impôt
    "45": "annee_revenus", # Année des revenus
    "46": "declarant1", # Déclarant 1
    "47": "numero_fiscal_d1", # Numéro fiscal du déclarant 1
    "48": "declarant2", # Déclarant 2
    "49": "numero_fiscal_d2", # Numéro fiscal du déclarant 2
    "4A": "date_mise_recouvrement", # Date de mise en recouvrement
    "4B": "date_declaration", # Date de la déclaration
    "4C": "date_enregistrement", # Date d'enregistrement
    "4D": "montant_don", # Montant du don (en €)
    "4E": "montant_droits", # Montant des droits payés (en €)
    "4F": "reference_enregistrement", # Référence d'enregistrement
    "4G": "nom_donataire", # Nom du donataire
    "4H": "nom_donateur", # Nom(s) du(es) donateur(s)
    "4I": "montant_taxable", # Montant Taxable (en €)
    "4J": "montant_cession", # Montant de la cession (en €)
    "4K": "nom_cessionnaire", # Nom du cessionnaire
    "4L": "nom_cedant", # Nom du cédant
    "4M": "taux_applicatif", # Taux applicatif (en %)
    "4N": "nom_prenom_declarant", # Nom et prénoms du déclarant (Attestation 2041-ASK)
    "4O": "adresse_declarant", # Adresse du déclarant
    "4P": "code_postal_declarant", # Code postal du déclarant
    "4Q": "commune_declarant", # Commune du déclarant
    "4R": "sip_gestionnaire", # SIP gestionnaire
    "4S": "millesime", # Millésime
    "4T": "administration_cantonale_suisse", # Administration cantonale suisse
    "4U": "denomination_sociale_employeur", # Dénomination sociale de l'employeur
    "4V": "impot_revenu_net", # Impôt sur le revue net
    "4W": "reste_a_payer", # Reste à payer
    "4X": "retenue_source", # Retenue à la source
    "4Y": "adresse_complete_domicile", # Adresse complète du domicile
    "4Z": "prelevements_sociaux_nets", # Prélèvements sociaux nets / Champ facultatif
    
    # Activités professionnelles & Bulletins de salaire
    "50": "siret_employeur", # SIRET de l'employeur
    "53": "debut_periode", # Début de période
    "54": "fin_periode", # Fin de période
    "55": "date_debut_contrat", # Date de début de contrat
    "57": "date_signature_contrat", # Date de signature du contrat
    "58": "salaire_net_imposable", # Salaire net imposable
    "59": "cumul_salaire_net", # Cumul du salaire net imposable
    "5A": "salaire_brut", # Salaire brut du mois
    "5L": "siret_rna", # Numéro de SIRET ou RNA (Autorisation Travail AES)
    "5M": "denomination_sociale", # Dénomination sociale
    "5N": "numero_dossier", # Numéro de dossier d'autorisation de travail
    "5Q": "nom_declarant", # Nom du déclarant
    "5R": "prenom_declarant", # Prénom du déclarant
    "5S": "fonction_declarant", # Fonction du déclarant
    "5T": "type_contrat", # Type de contrat de travail
    "5U": "duree_contrat", # Durée du contrat
    "5V": "nom_employeur", # Nom ou raison sociale de l'employeur (Attestation Activité Pro)
    "5W": "prenom_salarie", # Prénom du salarié (Attestation Activité Pro)
    "5X": "nom_salarie", # Nom du salarié (Attestation Activité Pro)
    "5Y": "date_debut_activite", # Date de début d'activité (Attestation Activité Pro)
    "5Z": "statut_activite", # Statut d'activité (Attestation Activité Pro)
    
    # Identités, MRZ, Documents Étrangers
    "60": "liste_prenoms", # Liste des prénoms
    "61": "prenom_employe", # Prénom de l'employé
    "62": "nom_employe", # Nom de l'employé / Nom patronymique
    "63": "nom_usage", # Nom d'usage
    "65": "type_piece", # Type de pièce d'identité
    "66": "numero_piece", # Numéro de la pièce d'identité
    "67": "nationalite", # Nationalité
    "68": "genre", # Genre
    "69": "date_naissance", # Date de naissance
    "6A": "lieu_naissance", # Lieu de naissance
    "6C": "pays_naissance", # Pays de naissance
    "6F": "mrz", # Machine Readable Zone (ZLA)
    "6G": "nom", # Nom (Courrier Permis à Points)
    "6H": "civilite", # Civilité
    "6J": "type_document_etranger", # Type de document étranger
    "6K": "numero_demande", # Numéro de la demande de document étranger
    "6L": "date_depot_demande", # Date de dépôt de la demande
    "6P": "autorisation", # Autorisation
    "6Q": "numero_etranger", # Numéro d'étranger
    "6U": "adresse_ligne4", # Ligne 4 de l'adresse postale du domicile
    "6W": "code_postal_domicile", # Code postal ou code cedex du domicile
    "6X": "commune_domicile", # Commune de l'adresse postale du domicile
    
    # Santé / Décès
    "70": "date_heure_deces", # Date et heure du décès
    "71": "date_heure_constat", # Date et heure du constat de décès
    "72": "nom_defunt", # Nom du défunt
    "73": "prenoms_defunt", # Prénoms du défunt
    "77": "commune_deces", # Commune de décès
    "78": "code_postal_deces", # Code postal de la commune de décès
    "7C": "obstacle_medico_legal", # Obstacle médico-légal
    "7D": "mise_en_biere", # Mise en bière
    "7E": "obstacle_conservation", # Obstacle aux soins de conservation
    "7G": "recherche_cause_deces", # Recherche de la cause du décès
    "7K": "code_nnc", # Code NNC
    "7M": "identification_medecin", # Identification du médecin
    "7P": "identifiant_certificat", # Identifiant du certificat
    
    # Permis, Chasse, Activités
    "80": "nom", # Nom (ArretesPermisConduire, CourrierPermisPoints, etc.)
    "81": "prenoms", # Prénom
    "82": "numero_carte", # Numéro de la carte
    "83": "organisme_tutelle", # Organisme de tutelle
    "85": "numero_permis", # Numéro de permis de chasser
    "86": "numero_licence", # Numéro de licence (Conducteur train / Permis)
    "87": "nom_patronymique", # Assuré - Nom patronymique (CertificatPreuveVie)
    "88": "identifiant_assure", # Assuré - Identifiant
    "8A": "date_debut_campagne", # Assuré - Date de début de campagne
    "8B": "identifiant_enquete", # Assuré - Identifiant enquête MCE
    "8C": "identifiant_certificat", # Vie Identifiant du certificat d'existence
    "8D": "date_emission_cert", # Vie Date émission certificat
    "8J": "indicateur_dematerialisation", # Contact - Indicateur de dématérialisation
    
    # Documents juridiques / Huissier
    "90": "identite_huissier", # Identité de l'huissier de justice
    "92": "identite_destinataire", # Identité ou raison sociale du destinataire
    "94": "intitule_acte", # Intitulé de l'acte
    "96": "date_signature_acte", # Date de signature de l'acte
    
    # Véhicules & Crit'Air
    "A0": "pays_immatriculation", # Pays ayant émis l'immatriculation du véhicule
    "A1": "immatriculation", # Immatriculation du véhicule
    "A2": "marque", # Marque du véhicule
    "A3": "nom_commercial", # Nom commercial du véhicule
    "A4": "vin", # Numéro de série du véhicule (VIN)
    "A5": "categorie", # Catégorie du véhicule
    "A6": "carburant", # Carburant
    "A7": "taux_co2", # Taux d'émission de CO2 du véhicule
    "A9": "classe_emission", # Classe d'émission polluante
    "AB": "type_lettre", # Type de lettre
    "AC": "numero_dossier", # N° Dossier
    "AH": "numero_carte", # Numéro de la carte (CMI)
    "AI": "date_expiration", # Date d'expiration initiale
    "AJ": "numero_evtc", # Numéro EVTC
    "AK": "numero_macaron", # Numéro de macaron
    "AL": "numero_carte_vtc", # Numéro de la carte (Carte T3P)
    "AM": "motif_surclassement", # Motif de sur-classement
    "AN": "kilometrage", # Kilométrage
    "AO": "numero_identification", # Numéro d'identification (DICEM)
    "AP": "type_engins", # Type d'engins
    "AQ": "numero_serie", # Numéro de série
    "AS": "couleur", # Couleur dominante
    "AT": "type_proprietaire", # Type de propriétaire
    "AW": "adresse_ligne4", # Ligne 4 de l'adresse postale du propriétaire
    "AY": "code_postal", # Code postal ou code cedex du propriétaire
    "AZ": "commune", # Commune de l'adresse postale du propriétaire
    
    # Diplômes & Académique
    "B0": "liste_prenoms", # Liste des prénoms
    "B1": "prenom", # Prénom
    "B2": "nom_patronymique", # Nom patronymique
    "B5": "nationalite", # Nationalité
    "B6": "genre", # Genre
    "B7": "date_naissance", # Date de naissance
    "B9": "pays_naissance", # Pays de naissance
    "BB": "numero_identification", # Numéro ou code d'identification de l'étudiant
    "BD": "niveau_diplome", # Niveau du diplôme selon la classification CEC
    "BG": "type_diplome", # Type de diplôme
    "BH": "domaine", # Domaine
    "BI": "mention", # Mention
    "BJ": "specialite", # Spécialité
    "BK": "numero_attestation_cve", # Numéro de l'Attestation de versement de la CVE
    
    # Cession de Véhicule
    "C1": "nom_vendeur", # Nom patronymique du vendeur
    "C2": "prenom_vendeur", # Prénom du vendeur
    "C3": "date_heure_cession", # Date et heure de la cession
    "C4": "date_signature_vendeur", # Date de la signature du vendeur
    "C6": "nom_acheteur", # Nom patronymique de l'acheteur
    "C7": "prenom_acheteur", # Prénom de l'acheteur
    "C8": "adresse_acheteur", # Ligne 4 de la norme adresse postale du domicile de l'acheteur
    "C9": "code_postal_acheteur", # Code postal ou code cedex du domicile de l'acheteur
    "CA": "commune_acheteur", # Commune du domicile de l'acheteur
    "CB": "numero_enregistrement", # N° d'enregistrement
    "CC": "date_enregistrement_siv" # Date et heure d'enregistrement dans le SIV
}

# Base de connaissances globale des longueurs fixes de la spécification ANTS (min_size == max_size)
LONGUEURS_FIXES = {
    # En-tête & Communs
    "06": 6, "07": 6, "08": 4, "09": 4, "0A": 9, "0B": 9,
    # Adresses / Localisation
    "1C": 8, "1G": 1, "1H": 1, "24": 5, "26": 2, "2B": 5, "2D": 2, "34": 2, "36": 4, "37": 4,
    # Impôts & Fiscalité (Vérifié sur Spec V3.3.8)
    "40": 13, "43": 1, "44": 13, "45": 4, "47": 13, "49": 13, "4A": 8, "4B": 8,
    # Social / Paie
    "50": 14, "51": 6, "52": 7, "53": 4, "54": 4, "55": 8, "56": 4, "57": 8, "5H": 5, "5J": 2, "5N": 21, "5T": 1,
    # Identités & Étranger
    "65": 2, "67": 2, "68": 1, "69": 8, "6B": 3, "6C": 2, "6I": 2, "6J": 1, "6K": 19, "6L": 8, "6N": 8, "6O": 8, "6R": 12, "6W": 5, "6Y": 2,
    # Décès
    "70": 12, "71": 12, "75": 8, "76": 1, "78": 5, "7A": 5, "7C": 1, "7D": 1, "7E": 1, "7F": 1, "7G": 1, "7H": 2, "7I": 1, "7J": 1, "7K": 13, "7L": 9, "7O": 1,
    # Permis / Chasse
    "85": 17, "86": 12, "96": 8,
    # Véhicules & Infractions
    "A0": 2, "A4": 17, "A5": 3, "A6": 2, "A7": 3, "A9": 3, "AA": 8, "AD": 4, "AE": 4, "AF": 1, "AG": 1, "AI": 8, "AJ": 13, "AK": 7, "AL": 11, "AN": 8, "AY": 5,
    # Études / Académique
    "B5": 2, "B6": 1, "B7": 8, "B9": 2, "BA": 1, "BD": 1, "BE": 3, "BF": 3, "BG": 2, "BK": 14,
    # Cession SIV
    "C0": 1, "C3": 12, "C4": 8, "C5": 1, "C9": 5, "CB": 10, "CC": 12
}


def parse_header(raw: str) -> dict:
    """
    Parse les premiers caractères du header 2D-Doc (nombre de caractères 
    en fonction de la version) et retourne un dict avec les champs du header.
    """

    if not raw.startswith("DC"):
        raise ParseError(f"Marqueur DC absent - ce n'est pas un 2D-Doc valide : {raw[:10]}")
    
    version = raw[2:4]
    
    if version in ("01","02"):
        if len(raw) < 22:
            raise ParseError(f"Header trop court ({len(raw)} caractères, minimum 22)")
        return {
            "marqueur_id" : raw[0:2],
            "version_id" : version,
            "ca_id" : raw[4:8],
            "certif_id" : raw[8:12],
            "date_emission" : raw[12:16],
            "date_signature" : raw[16:20],
            "code_identification_doc" : raw[20:22],
            "identifiant_perimetre": None,
            "pays_emetteur" : None,
            "_data_offset": 22
        }
    
    elif version == "03":
        if len(raw) < 24:
            raise ParseError(f"Header v03 trop court ({len(raw)} chars, min 24)")
        return {
            "marqueur_id" : raw[0:2],
            "version_id" : version,
            "ca_id" : raw[4:8],
            "certif_id" : raw[8:12],
            "date_emission" : raw[12:16],
            "date_signature" : raw[16:20],
            "code_identification_doc" : raw[20:22],
            "identifiant_perimetre": raw[22:24],
            "pays_emetteur" : None,
            "_data_offset" : 24
        }

    elif version == "04":
        if len(raw) < 26:
            raise ParseError(f"Header v04 trop court ({len(raw)} chars, min 26)")
        return {
            "marqueur_id" : raw[0:2],
            "version_id" : version,
            "ca_id" : raw[4:8],
            "certif_id" : raw[8:12],
            "date_emission" : raw[12:16],
            "date_signature" : raw[16:20],
            "code_identification_doc" : raw[20:22],
            "identifiant_perimetre": raw[22:24],
            "pays_emetteur" : raw[24:26],
            "_data_offset" : 26
        }      
    else:
        raise ParseError(f"Version non supportée : '{version}'")


def parse_champs(data_str: str, allowed_ids: set) -> dict:
    """
    Parse la partie données de manière robuste en respectant les spécifications ANTS.
    Un identifiant variable prend TOUTE la chaîne jusqu'au prochain séparateur GS.
    """
    champs = {}
    
    data_part = data_str.replace(RS, "")
    segments = data_part.split(GS)

    for segment in segments:
        if len(segment) < 2:
            continue

        position = 0
        len_seg = len(segment)

        # On boucle à l'intérieur du segment
        while position <= len_seg - 2:
            identifiant = segment[position:position + 2]

            # Si l'identifiant est inconnu ou non autorisé pour ce traitement, on avance de 1 pour tenter de se resynchroniser (sécurité).
            if identifiant not in FIELD_MAP:
                position += 1
                continue

            start_val = position + 2

            # CAS 1 : L'identifiant est de taille fixe
            if identifiant in LONGUEURS_FIXES:
                taille = LONGUEURS_FIXES[identifiant]
                next_pos = start_val + taille
                
                # Sécurité si le flux est mal formé
                if next_pos > len_seg:
                    next_pos = len_seg
                
                valeur = segment[start_val:next_pos].strip()
                if valeur:
                    champs[identifiant] = valeur
                
                # On avance directement après la valeur fixe.
                position = next_pos

            # CAS 2 : L'identifiant est de taille variable
            else:
                valeur = segment[start_val:].strip()
                if valeur:
                    champs[identifiant] = valeur
                
                # On force la sortie du segment puisqu'on a tout consommé
                break

    return champs


def parse_2ddoc(raw: str) -> mod.DocFields:
    """
    Point d'entrée principal.
    Reçoit la chaîne brute du Data Matrix.
    Retourne une instance DocFields (ou sous-classe) remplie et 
    directement compatible avec le module de validation cryptographique.
    """
    import logging
    logger = logging.getLogger(__name__)

    if "<US>" in raw or "<GS>" in raw or "<RS>" in raw:
        raw = raw.replace("<GS>", GS).replace("<US>", US).replace("<RS>", RS)

    if US in raw:
        data_part, signature = raw.rsplit(US, 1)
    else:
        data_part = raw
        signature = None

    data_part = data_part.strip()

    # Extraction et traitement de l'en-tête (Header)
    header = parse_header(data_part)
    offset = header.pop("_data_offset")
    code_doc = header["code_identification_doc"]

    # Routage dynamique vers la classe de modèle ANTS adéquate
    classe = mod.DOC_TYPE_MAP.get(code_doc)
    if classe is None:
        logger.warning(f"Type '{code_doc}' inconnu — Repli vers DocFields")
        classe = mod.DocFields

    # Liste des attributs attendus par l'initialiseur de la Dataclass cible
    champs_attendus_dataclass = {f.name for f in dataclasses.fields(classe)}

    # On autorise le parsing de TOUS les identifiants connus de la spécification générale
    allowed_ids = set(FIELD_MAP.keys())

    # Extraction séquentielle des champs du message (Lookahead sur tailles fixes/variables)
    champs_extraits = parse_champs(data_part[offset:], allowed_ids=allowed_ids)

    # Préparation des arguments d'instanciation de l'objet
    kwargs = dict(header)
    kwargs["signature_brute"] = signature
    kwargs["champs_extra"] = {}

    for identifiant, valeur in champs_extraits.items():
        nom_attribut = FIELD_MAP.get(identifiant)
        
        # Si l'attribut est explicitement défini dans le modèle typé
        if nom_attribut and nom_attribut in champs_attendus_dataclass:
            kwargs[nom_attribut] = valeur
        
        # On peuple obligatoirement 'champs_extra' avec la clé brute à 2 caractères.
        kwargs["champs_extra"][identifiant] = valeur

    try:
        return classe(**kwargs)
    except TypeError as e:
        raise ParseError(f"Erreur lors de l'instanciation de '{classe.__name__}' : {e}")


def parse_extractor_output(extractor_data: Dict[str, Any]) -> Optional[mod.DocFields]:
    """
    Prend en entrée la structure dictionnaire complète issue de extractor.py,
    isole la chaîne de caractères brute 2D-Doc et appelle parse_2ddoc.
    """
    validation_info = extractor_data.get("document_validation", {})
    unique_codes = validation_info.get("unique_codes", [])
    
    if not unique_codes or unique_codes[0] is None:
        for page in extractor_data.get("pages", []):
            if page.get("code_2d"):
                unique_codes = [page["code_2d"]]
                break
                
    if not unique_codes or unique_codes[0] is None:
        return None
        
    try:
        return parse_2ddoc(unique_codes[0])
    except ParseError:
        return None