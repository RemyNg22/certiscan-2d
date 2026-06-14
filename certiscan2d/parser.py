import certiscan2d.models as mod

# Séparateurs définis dans la spec ANTS
GS = "\x1d" # Group Separator - sépare les champs de données
US = "\x1f" # Unit Separator - sépare les données de la signature
RS = "\x1e" # Information Separator Two - tronque un mot en deux

class ParseError(Exception):
    pass

# Correspondance complète identifiant ANTS -> nom d'attribut dans la dataclass
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
    "43": "nombre_parts", # Nombre de parts
    "44": "reference_avis", # Référence d'avis d'impôt
    "45": "annee_revenus", # Année des revenus
    "46": "declarant1", # Déclarant 1
    "47": "numero_fiscal_d1", # Numéro fiscal du déclarant 1
    "4A": "date_mise_recouvrement", # Date de mise en recouvrement
    "4B": "date_declaration", # Date de la déclaration
    "4C": "date_enregistrement", # Date d'enregistrement
    "4D": "montant_don", # Montant du don (en €)
    "4E": "montant_droits", # Montant des droits payés (en €)
    "4F": "reference_enregistrement", # Référence d'enregistrement
    "4G": "nom_donataire", # Nom du donataire
    "4H": "nom_donateur", # Nom(s) du(es) donateur(s)
    "4J": "montant_cession", # Montant de la cession (en €)
    "4K": "nom_cessionnaire", # Nom du cessionnaire
    "4L": "nom_cedant", # Nom du cédant
    "4N": "nom_prenom_declarant", # Nom et prénoms du déclarant (Attestation 2041-ASK)
    "40": "adresse_declarant", # Adresse du déclarant
    "4P": "code_postal_declarant", # Code postal du déclarant
    "4Q": "commune_declarant", # Commune du déclarant
    "4R": "sip_gestionnaire", # SIP gestionnaire
    "4S": "millesime", # Millésime
    "4V": "impot_revenu_net", # Impôt sur le revenu net
    "4W": "reste_a_payer", # Reste à payer
    "4X": "retenue_source", # Retenue à la source
    "4Z": "champ_facultatif", # Champ facultatif (Avis V2 & V3)
    
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
    
    # Identités, MRZ, Documents Étrangers (Série 6x)
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
    
    # Santé / Décès (Série 7x)
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
    
    # Permis, Chasse, Activités (Série 8x)
    "80": "nom", # Nom (ArretesPermisConduire, CourrierPermisPoints, etc.)
    "81": "prenoms", # Prénoms
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
    
    # Documents juridiques / Huissier (Série 9x)
    "90": "identite_huissier", # Identité de l'huissier de justice
    "92": "identite_destinataire", # Identité ou raison sociale du destinataire
    "94": "intitule_acte", # Intitulé de l'acte
    "96": "date_signature_acte", # Date de signature de l'acte
    
    # Véhicules & Crit'Air (Série Ax)
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
    
    # Diplômes & Académique (Série Bx)
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
    
    # Cession de Véhicule (Série Cx)
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
            "marqueur_id" : raw[0:2], # toujours "DC"
            "version_id" : version, # ex: "01"
            "ca_id" : raw[4:8], # ex: "FR06"
            "certif_id" : raw[8:12], # ex: "FPE6"
            "date_emission" : raw[12:16], # ex: "FFFF"
            "date_signature" : raw[16:20], # ex: "2471"
            "code_identification_doc" : raw[20:22], # ex: "28"
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
        if len(raw) < 28:
            raise ParseError(f"Header v04 trop court ({len(raw)} chars, min 28)")
        
        return {
            "marqueur_id" : raw[0:2],
            "version_id" : version,
            "ca_id" : raw[4:10],
            "certif_id" : raw[10:14],
            "date_emission" : raw[14:18],
            "date_signature" : raw[18:22],
            "code_identification_doc" : raw[22:24],
            "identifiant_perimetre": raw[24:26],
            "pays_emetteur" : raw[26:28],
            "_data_offset" : 28
        }      

    else:
        raise ParseError(f"Version non supportée : '{version}' — versions gérées : 01, 02, 03, 04")


def parse_champs(data_str: str) -> dict:
    """
    Parse la partie données (après header, avant signature).
    Plusieurs identifiants peuvent être concaténés dans un même segment GS.
    Le RS tronque un mot en deux parties à reconstruire.
    """
    champs = {}

    data_str = data_str.replace(RS, "")

    for segment in data_str.split(GS):
        if len(segment) < 2:
            continue

        position = 0

        while position <= len(segment) - 2:
            identifiant = segment[position:position + 2]

            if identifiant not in FIELD_MAP:
                position += 1
                continue

            next_pos = position + 2

            while next_pos < len(segment):
                if next_pos + 1 < len(segment) and segment[next_pos:next_pos + 2] in FIELD_MAP:
                    break
                next_pos += 1

            valeur = segment[position + 2:next_pos].strip()

            if valeur:
                champs[identifiant] = valeur

            position = next_pos

    return champs


def parse_2ddoc(raw:str) -> mod.DocFields:
    """
    Point d'entrée principal.
    Reçoit la chaîne brute du Data Matrix.
    Retourne une instance DocFields (ou sous-classe) remplie.
    """
    pass