"""
Module certificate.py — Génération à la volée de certificats d'analyse PDF.
Principes de sécurité appliqués :
- Le PDF est généré entièrement en mémoire vive (BytesIO) et streamé.
- Aucune persistance sur disque.
- Les signatures et données sensibles sont encapsulées de façon stricte.
"""

import io
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


def generer_certificat_pdf(rapport_dict: dict) -> io.BytesIO:
    """
    Génère un rapport d'audit au format PDF à partir des données du rapport (dictionnaire).
    Renvoie un flux de octets (BytesIO) prêt à être envoyé par send_file() dans Flask.
    """
    buffer = io.BytesIO()
    
    # 1. Initialisation du document (Marges de 2 cm)
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=54,
        leftMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    
    histoire = []
    styles = getSampleStyleSheet()
    
    # 2. Définition des palettes de couleurs GRC (Graphiques & Professionnelles)
    STATUT = rapport_dict.get("statut", "INVALID").upper()
    
    # Couleur du bandeau selon le verdict de conformité
    if STATUT == "VALID":
        couleur_principale = colors.HexColor("#2ecc71")  # Vert Émeraude
        texte_verdict = "DOCUMENT VALIDE & CONFORME"
    elif STATUT == "SUSPICIOUS":
        couleur_principale = colors.HexColor("#f39c12")  # Orange Alerte
        texte_verdict = "ATTENTION : COHÉRENCE DOUTEUSE"
    else:
        couleur_principale = colors.HexColor("#e74c3c")  # Rouge Alerte Falsification
        texte_verdict = "DOCUMENT COMPROMIS / NON CONFORME"
        
    couleur_texte_sombre = colors.HexColor("#2c3e50")
    couleur_gris_neutre = colors.HexColor("#7f8c8d")
    couleur_fond_bloc = colors.HexColor("#f8f9fa")
    couleur_bordure = colors.HexColor("#bdc3c7")

    # 3. Styles personnalisés pour le rapport
    style_titre = ParagraphStyle(
        'TitreCertificat',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=couleur_texte_sombre,
        spaceAfter=6
    )
    
    style_sous_titre = ParagraphStyle(
        'SousTitreCertificat',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=couleur_gris_neutre,
        spaceAfter=20
    )
    
    style_verdict = ParagraphStyle(
        'VerdictStyle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.white,
        alignment=TA_CENTER
    )
    
    style_h2 = ParagraphStyle(
        'SectionH2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=couleur_texte_sombre,
        spaceBefore=14,
        spaceAfter=8
    )

    style_corps = ParagraphStyle(
        'CorpsCertificat',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=couleur_texte_sombre
    )
    
    style_corps_bold = ParagraphStyle(
        'CorpsBoldCertificat',
        parent=style_corps,
        fontName='Helvetica-Bold'
    )

    style_code = ParagraphStyle(
        'CodeStyle',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#2c3e50")
    )

    # --- ENTÊTE DU DOCUMENT ---
    histoire.append(Paragraph("CertiScan 2D — Rapport d'Audit", style_titre))
    
    # Date et heure de l'analyse (UTC ou locale)
    date_analyse = rapport_dict.get("horodatage", datetime.now(timezone.utc).strftime("%d/%m/%Y"))
    heure_actuelle = datetime.now().strftime("%H:%M:%S")
    metadata_texte = f"Généré le {date_analyse} à {heure_actuelle} | Identifiant d'analyse : {uuid_court()}"
    histoire.append(Paragraph(metadata_texte, style_sous_titre))
    
    # --- BANDEAU VISUEL DE VERDICT (PREMIÈRE VUE RÉSULTAT) ---
    table_verdict_data = [[Paragraph(texte_verdict, style_verdict)]]
    table_verdict = Table(table_verdict_data, colWidths=[504])
    table_verdict.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), couleur_principale),
        ('PADDING', (0, 0), (-1, -1), 12),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 14),
    ]))
    histoire.append(table_verdict)
    histoire.append(Spacer(1, 15))

    # --- SECTION 1 : APERÇU / MÉTADONNÉES DU DOCUMENT ANALYSÉ ---
    histoire.append(Paragraph("Aperçu du document analysé", style_h2))
    
    donnees_apercu = [
        [Paragraph("Nom du fichier d'origine :", style_corps_bold), Paragraph(rapport_dict.get("nom_fichier_origine", "Inconnu"), style_corps)],
        [Paragraph("Type de document détecté :", style_corps_bold), Paragraph(rapport_dict.get("type_document_libelle", "Non identifié"), style_corps)],
        [Paragraph("Message de conformité :", style_corps_bold), Paragraph(rapport_dict.get("message_principal", "-"), style_corps)],
    ]
    
    table_apercu = Table(donnees_apercu, colWidths=[150, 354])
    table_apercu.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), couleur_fond_bloc),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, couleur_bordure),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    histoire.append(table_apercu)
    histoire.append(Spacer(1, 15))

    # --- SECTION 2 : SCORE ET RÉSULTAT DES ÉTAPES DU PIPELINE ---
    histoire.append(Paragraph("Détail du pipeline de contrôle de sécurité", style_h2))
    
    # En-tête du tableau des étapes
    donnees_etapes = [[
        Paragraph("Étape d'Audit", style_corps_bold),
        Paragraph("Statut", style_corps_bold),
        Paragraph("Détails / Métadonnées observées", style_corps_bold)
    ]]
    
    # Parcours des étapes de l'orchestrateur
    for etape in rapport_dict.get("etapes", []):
        statut_etape = etape.get("statut", "ignore").upper()
        # Formatage visuel du statut de la sous-étape
        if statut_etape == "OK":
            texte_statut = "<font color='#2ecc71'><b>SUCCÈS</b></font>"
        elif statut_etape == "ECHEC":
            texte_statut = "<font color='#e74c3c'><b>ÉCHEC</b></font>"
        else:
            texte_statut = "<font color='#7f8c8d'><b>IGNORÉ</b></font>"
            
        donnees_etapes.append([
            Paragraph(etape.get("nom", "Étape"), style_corps),
            Paragraph(texte_statut, style_corps),
            Paragraph(etape.get("message", "-"), style_corps)
        ])
        
    table_etapes = Table(donnees_etapes, colWidths=[130, 70, 304])
    table_etapes.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#eaeded")),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('LINEBELOW', (0, 0), (-1, 0), 1, couleur_texte_sombre),
        ('GRID', (0, 0), (-1, -1), 0.5, couleur_bordure),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    histoire.append(table_etapes)
    histoire.append(Spacer(1, 15))

    # --- SECTION 3 : INFRASTRUCTURE DE CONFIANCE CRYPTOGRAPHIQUE ---
    histoire.append(Paragraph("Validation de l'Infrastructure de Confiance (Signature 2D-Doc)", style_h2))
    
    # Récupération de la signature tronquée
    sig_apercu = rapport_dict.get("signature_apercu") or "Aucune signature présente ou lisible"
    
    donnees_crypto = [
        [Paragraph("Autorité de Certification (CA ID) :", style_corps_bold), Paragraph(rapport_dict.get("autorite_certification") or "Non identifiée", style_corps)],
        [Paragraph("Identifiant du Certificat (Cert ID) :", style_corps_bold), Paragraph(rapport_dict.get("identifiant_certificat") or "Non identifié", style_corps)],
        [Paragraph("Empreinte / Signature cryptographique :", style_corps_bold), Paragraph(sig_apercu, style_code)],
    ]
    
    table_crypto = Table(donnees_crypto, colWidths=[180, 324])
    table_crypto.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), couleur_fond_bloc),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, couleur_bordure),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    histoire.append(table_crypto)
    histoire.append(Spacer(1, 15))

    # --- SECTION 4 : RECOUPEMENT ET COHÉRENCE DES DONNÉES (OCR VS DATA MATRIX) ---
    champs_verifies = rapport_dict.get("champs_verifies", {})
    if champs_verifies:
        histoire.append(Paragraph("Recoupement des données de surface (Analyse de cohérence)", style_h2))
        
        donnees_champs = [[
            Paragraph("Donnée Audité", style_corps_bold),
            Paragraph("Valeur Sécurisée (2D-Doc)", style_corps_bold),
            Paragraph("Statut", style_corps_bold)
        ]]
        
        for cle_champ, infos in champs_verifies.items():
            match_status = infos.get("statut", "UNKNOWN").upper()
            if match_status == "MATCH":
                txt_match = "<font color='#2ecc71'><b>CONCORDANCE</b></font>"
            elif match_status == "CONTRADICTION":
                txt_match = "<font color='#e74c3c'><b>ÉCART / FALSIFICATION</b></font>"
            else:
                txt_match = "<font color='#f39c12'><b>NON TROUVÉ (OCR)</b></font>"
                
            donnees_champs.append([
                Paragraph(cle_champ, style_corps),
                Paragraph(str(infos.get("attendu", "-")), style_corps),
                Paragraph(txt_match, style_corps)
            ])
            
        table_champs = Table(donnees_champs, colWidths=[150, 224, 130])
        table_champs.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#eaeded")),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('LINEBELOW', (0, 0), (-1, 0), 1, couleur_texte_sombre),
            ('GRID', (0, 0), (-1, -1), 0.5, couleur_bordure),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        histoire.append(table_champs)

    # --- PIED DE PAGE ET CLAUSE DE NON-PERSISTANCE ---
    histoire.append(Spacer(1, 30))
    histoire.append(HRFlowable(width="100%", thickness=0.5, color=couleur_bordure, spaceAfter=15))
    
    style_footer = ParagraphStyle(
        'AvisSecuFooter',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8,
        leading=11,
        textColor=couleur_gris_neutre,
        alignment=TA_CENTER
    )
    
    clause_securite = (
        "Avis de confidentialité : Ce document constitue un rapport technique éphémère d'analyse documentaire. "
        "Conformément à la politique de sécurité CertiScan 2D, aucune métadonnée ni fichier source n'a été conservé "
        "sur nos serveurs à l'issue de cet audit. Ce certificat fait foi uniquement au moment de sa génération."
    )
    histoire.append(Paragraph(clause_securite, style_footer))

    # 4. Construction finale du document
    doc.build(histoire)
    
    # Repositionnement du curseur au début du flux de octets pour la lecture de Flask
    buffer.seek(0)
    return buffer


def uuid_court() -> str:
    """Génère une sous-clé d'audit courte pour le suivi d'analyse sans stocker d'id persistant."""
    import uuid
    return uuid.uuid4().hex[:8].upper()