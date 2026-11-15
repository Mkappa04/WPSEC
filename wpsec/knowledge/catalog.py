"""Catalogo dei risultati: l'UNICA fonte di gravità, tipo, CWE e CVSS.

Regole (documentate in docs/METHODOLOGY.md):
  - la gravità di partenza è una scelta motivata qui (`rationale`), non dell'IA;
  - la CWE è indicata solo quando il legame con la debolezza è diretto; altrimenti è
    vuota (es. XML-RPC: è una superficie d'attacco, non una debolezza in sé);
  - il CVSS NON viene assegnato ai problemi di hardening o di esposizione informativa:
    senza uno scenario di sfruttamento concreto il punteggio sarebbe inventato.
    Il campo esiste per i casi in cui il vettore sia giustificabile.
Le CWE vanno ricontrollate su https://cwe.mitre.org prima della consegna della tesi
(vedi docs/METHODOLOGY.md, sezione "Verifica del catalogo").
"""

from __future__ import annotations

from dataclasses import dataclass

from wpsec.core.models import FindingKind, Severity

CATALOG_VERSION = "2026.11-1"


@dataclass(frozen=True)
class FindingDefinition:
    check_id: str
    title: str
    category: str
    kind: FindingKind
    severity: Severity
    rationale: str
    impact: str
    cwe: str = ""
    cvss_vector: str = ""
    legacy_id: str = ""
    remediation_id: str = ""
    references: tuple[str, ...] = ()


_D = FindingDefinition
K, S = FindingKind, Severity

_DEFINITIONS = [
    # ------------------------------------------------------------ ricognizione
    _D("recon.waf", "Rilevamento WAF/CDN", "recon", K.INFORMATIONAL, S.INFO,
       "Solo contesto: un WAF può bloccare alcuni controlli e rendere inconcludenti gli esiti.",
       "Nessun impatto diretto.", legacy_id="waf"),
    _D("recon.wordpress", "Identificazione di WordPress", "recon", K.INFORMATIONAL, S.INFO,
       "Contesto: decide se attivare il WordPress Security Agent.", "Nessun impatto diretto."),
    _D("recon.technologies", "Tecnologie e percorsi pubblici", "recon", K.INFORMATIONAL, S.INFO,
       "Contesto per l'analisi.", "Nessun impatto diretto."),
    # ------------------------------------------------------------ WordPress
    _D("wp.users_rest", "Esposizione utenti via REST API", "wordpress", K.INFORMATION_EXPOSURE,
       S.MEDIUM,
       "Gli username sono metà delle credenziali: la loro esposizione rende mirati i tentativi "
       "di indovinare le password. Media perché non dà accesso da sola.",
       "Un attaccante ottiene l'elenco degli username validi e può concentrare su di essi "
       "attacchi alle password (tramite login o XML-RPC).",
       cwe="CWE-200", legacy_id="utenti", remediation_id="wp.users_rest",
       references=("https://developer.wordpress.org/rest-api/reference/users/",)),
    _D("wp.author_enum", "Enumerazione autori (?author=1)", "wordpress", K.INFORMATION_EXPOSURE,
       S.LOW,
       "Rivela uno username alla volta; bassa perché l'informazione è spesso già pubblica "
       "(firma degli articoli).",
       "Un attaccante può ricavare gli username degli autori uno per uno.",
       cwe="CWE-200", legacy_id="author", remediation_id="wp.author_enum"),
    _D("wp.xmlrpc", "XML-RPC attivo", "wordpress", K.MISCONFIGURATION, S.MEDIUM,
       "XML-RPC accetta login e, con system.multicall, centinaia di tentativi per richiesta. "
       "Media se multicall è presente, bassa altrimenti (regola nel Risk Agent).",
       "Superficie per attacchi alle password amplificati e per abusi di pingback.",
       legacy_id="xmlrpc", remediation_id="wp.xmlrpc",
       references=("https://codex.wordpress.org/XML-RPC_Support",)),
    _D("wp.version_disclosure", "Versione WordPress esposta", "wordpress", K.INFORMATION_EXPOSURE,
       S.LOW,
       "Facilita la ricerca di vulnerabilità note per quella versione; bassa perché non è un "
       "difetto sfruttabile di per sé (lo è solo una versione vulnerabile non aggiornata).",
       "Un attaccante può scegliere exploit noti per la versione rilevata.",
       cwe="CWE-200", legacy_id="versione", remediation_id="wp.version_disclosure"),
    _D("wp.directory_listing", "Directory listing in uploads", "wordpress", K.MISCONFIGURATION,
       S.MEDIUM,
       "Rende consultabili tutti i file caricati, compresi quelli non collegati a pagine "
       "pubbliche (bozze, documenti, backup).",
       "Accesso a file non destinati alla pubblicazione.",
       cwe="CWE-548", legacy_id="uploads", remediation_id="wp.directory_listing"),
    _D("wp.debug_log", "File debug.log accessibile", "wordpress", K.INFORMATION_EXPOSURE, S.MEDIUM,
       "Il log di debug può contenere percorsi del server, query e talvolta dati personali o "
       "segreti. Media: l'impatto dipende dal contenuto, che la piattaforma non conserva.",
       "Fuga di informazioni interne utili ad attacchi successivi.",
       cwe="CWE-538", remediation_id="wp.debug_log"),
    _D("wp.login_page", "Pagina di login WordPress", "wordpress", K.INFORMATIONAL, S.INFO,
       "La pagina di login è una funzione normale: non è una vulnerabilità. Si registra come "
       "contesto per le raccomandazioni (limitazione dei tentativi, 2FA).",
       "Nessun impatto diretto."),
    # ------------------------------------------------------------ HTTP
    _D("http.header.hsts", "HSTS assente o debole", "http", K.MISCONFIGURATION, S.LOW,
       "Senza HSTS il primo accesso può avvenire in HTTP ed essere intercettato su reti non fidate.",
       "Possibile downgrade a HTTP e intercettazione di cookie su reti ostili.",
       cwe="CWE-319", legacy_id="header", remediation_id="http.headers"),
    _D("http.header.csp", "Content-Security-Policy assente o debole", "http", K.MISCONFIGURATION,
       S.LOW,
       "Il CSP è una difesa in profondità: la sua assenza non crea un XSS, ma ne aumenta "
       "l'impatto se uno esiste.",
       "Un'eventuale XSS (es. in un plugin) non verrebbe mitigata dal browser.",
       cwe="CWE-693", legacy_id="header", remediation_id="http.headers"),
    _D("http.header.xfo", "Protezione dal clickjacking assente", "http", K.MISCONFIGURATION, S.LOW,
       "Le pagine possono essere incorporate in iframe di altri siti.",
       "Clickjacking: l'utente può essere indotto a cliccare azioni nascoste.",
       cwe="CWE-1021", legacy_id="header", remediation_id="http.headers"),
    _D("http.header.xcto", "X-Content-Type-Options assente", "http", K.MISCONFIGURATION, S.LOW,
       "Difesa in profondità contro il MIME sniffing.",
       "File caricati potrebbero essere interpretati come script da browser datati.",
       cwe="CWE-693", legacy_id="header", remediation_id="http.headers"),
    _D("http.header.referrer", "Referrer-Policy assente o permissiva", "http", K.MISCONFIGURATION,
       S.LOW,
       "I browser moderni applicano già 'strict-origin-when-cross-origin' come predefinito: "
       "impatto limitato.",
       "Parametri presenti negli URL potrebbero essere inviati ad altri siti.",
       legacy_id="header", remediation_id="http.headers"),
    _D("http.header.permissions", "Permissions-Policy assente", "http", K.MISCONFIGURATION, S.LOW,
       "Hardening: limita le API del browser disponibili a script di terze parti.",
       "Script malevoli o compromessi potrebbero usare API non necessarie al sito.",
       cwe="CWE-693", legacy_id="header", remediation_id="http.headers"),
    _D("http.info_disclosure", "Header che rivelano software e versioni", "http",
       K.INFORMATION_EXPOSURE, S.LOW,
       "Come la versione di WordPress: facilita la scelta di exploit noti.",
       "Un attaccante conosce software e versioni del server.",
       cwe="CWE-200", remediation_id="http.info_disclosure"),
    _D("http.cookies", "Cookie senza attributi di sicurezza", "http", K.MISCONFIGURATION, S.LOW,
       "Riguarda i cookie impostati sulla home senza login; l'impatto dipende dal loro uso.",
       "Cookie leggibili da script (senza HttpOnly) o inviati in chiaro (senza Secure).",
       remediation_id="http.cookies"),
    _D("http.https_redirect", "HTTP non reindirizzato a HTTPS", "http", K.MISCONFIGURATION,
       S.MEDIUM,
       "Il sito risponde anche in chiaro: credenziali e cookie possono transitare senza cifratura.",
       "Intercettazione o modifica del traffico su reti non fidate.",
       cwe="CWE-319", remediation_id="http.https_redirect"),
    # ------------------------------------------------------------ TLS
    _D("tls.certificate", "Certificato TLS non valido o in scadenza", "tls", K.MISCONFIGURATION,
       S.MEDIUM,
       "Un certificato non valido abitua gli utenti a ignorare gli avvisi del browser; uno in "
       "scadenza causerà un'interruzione del servizio.",
       "Avvisi di sicurezza per i visitatori o possibilità di intercettazione.",
       remediation_id="tls.certificate"),
    _D("tls.protocol", "Protocollo TLS obsoleto", "tls", K.MISCONFIGURATION, S.MEDIUM,
       "TLS 1.0 e 1.1 sono deprecati (RFC 8996).",
       "Cifratura più debole e incompatibilità con i requisiti attuali.",
       remediation_id="tls.protocol", references=("https://www.rfc-editor.org/rfc/rfc8996",)),
    _D("tls.https", "Disponibilità di HTTPS", "tls", K.INFORMATIONAL, S.INFO,
       "Contesto: con un target HTTP i controlli TLS e HSTS non sono applicabili.",
       "Nessun impatto valutabile."),
    # ------------------------------------------------------------ ZAP
    _D("zap.alert", "Avviso di OWASP ZAP (analisi passiva)", "zap", K.MISCONFIGURATION, S.LOW,
       "Gravità e CWE sono quelle indicate da ZAP (fonte esterna, riportata come tale).",
       "Vedi la descrizione di ZAP."),
]

CATALOG: dict[str, FindingDefinition] = {d.check_id: d for d in _DEFINITIONS}

# CWE per i cookie: scelta in base all'attributo mancante (sempre dal catalogo)
COOKIE_CWE = {"secure": "CWE-614", "httponly": "CWE-1004"}


def get_definition(check_id: str) -> FindingDefinition:
    if check_id.startswith("zap.") and check_id not in CATALOG:
        return CATALOG["zap.alert"]
    return CATALOG[check_id]
