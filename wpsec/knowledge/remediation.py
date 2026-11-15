"""Correzioni verificate a mano (NON generate dall'IA).

Derivano dal dizionario FIX della v3, con in più: configurazione Nginx, rischi della
correzione e istruzioni per verificare che il problema sia risolto. La piattaforma
NON applica mai le correzioni al sito: le propone soltanto.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RemediationTemplate:
    id: str
    title: str
    summary: str
    wordpress: str = ""
    apache: str = ""
    nginx: str = ""
    risks: str = ""
    verification: str = ""
    references: tuple[str, ...] = ()


_T = RemediationTemplate

_TEMPLATES = [
    _T("wp.users_rest", "Nascondere gli utenti della REST API",
       "Rimuovere gli endpoint /wp/v2/users per i visitatori non autenticati.",
       wordpress="""Plugin per snippet (es. Code Snippets) o functions.php di un CHILD THEME.
Incolla SOLO queste righe, senza <?php e senza ?>:

add_filter('rest_endpoints', function ($endpoints) {
    if (!is_user_logged_in()) {
        unset($endpoints['/wp/v2/users']);
        unset($endpoints['/wp/v2/users/(?P<id>[\\d]+)']);
    }
    return $endpoints;
});""",
       risks="Plugin o app che leggono gli autori via REST senza login (alcuni temi headless, "
             "integrazioni) smettono di vederli. L'editor a blocchi non è toccato (usa il login).",
       verification="Da un browser NON autenticato aprire /wp-json/wp/v2/users e "
                    "/?rest_route=/wp/v2/users: entrambi devono rispondere 401 o 404.\n"
                    "curl -s -o /dev/null -w '%{http_code}' https://SITO/wp-json/wp/v2/users"),
    _T("wp.author_enum", "Bloccare l'enumerazione ?author=N",
       "Reindirizzare le richieste con il parametro author alla home.",
       wordpress="""Snippet (senza <?php):

add_action('template_redirect', function () {
    if (!is_admin() && isset($_GET['author'])) {
        wp_redirect(home_url(), 301);
        exit;
    }
});""",
       apache="""# .htaccess, prima delle regole di WordPress
RewriteEngine On
RewriteCond %{QUERY_STRING} (^|&)author=\\d+ [NC]
RewriteRule ^ /? [L,R=301]""",
       nginx="""if ($args ~* "(^|&)author=\\d+") { return 301 /; }""",
       risks="Gli archivi autore restano raggiungibili con l'URL /author/nome/: lo username "
             "resta visibile se il tema lo pubblica. Per nasconderlo serve anche un 'nicename' "
             "diverso dallo username.",
       verification="curl -sI 'https://SITO/?author=1' | grep -i location  -> non deve contenere /author/"),
    _T("wp.xmlrpc", "Disabilitare XML-RPC",
       "Bloccare xmlrpc.php, preferibilmente a livello di server web.",
       apache="""<Files xmlrpc.php>
    Require all denied
</Files>""",
       nginx="location = /xmlrpc.php { deny all; }",
       wordpress="""Via codice (senza <?php), se non si può toccare il server:

add_action('init', function () {
    if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
        status_header(403);
        exit;
    }
}, 0);

ATTENZIONE: add_filter('xmlrpc_enabled', '__return_false') da solo NON basta:
blocca solo i metodi con login e lascia raggiungibile system.listMethods.""",
       risks="Può rompere Jetpack, l'app mobile WordPress e i pingback/trackback.",
       verification="curl -s -X POST -H 'Content-Type: text/xml' --data "
                    "'<methodCall><methodName>system.listMethods</methodName></methodCall>' "
                    "https://SITO/xmlrpc.php  -> deve rispondere 403 (o <fault>)"),
    _T("wp.version_disclosure", "Nascondere la versione di WordPress",
       "Rimuovere il tag generator da HTML e feed; soprattutto, mantenere WordPress aggiornato.",
       wordpress="""Snippet (senza <?php). Il filtro 'the_generator' copre sia la home sia i feed;
remove_action('wp_head', 'wp_generator') da solo lascia la versione nei feed RSS.

add_filter('the_generator', '__return_empty_string');

Il parametro ?ver= degli script di wp-includes può rivelarla ancora: va gestito con
un plugin di ottimizzazione o accettato, perché la vera difesa è l'aggiornamento.""",
       apache="""# readme.html contiene informazioni sull'installazione
<Files readme.html>
    Require all denied
</Files>""",
       nginx="location = /readme.html { deny all; }",
       risks="Nessun rischio funzionale. Nascondere la versione non sostituisce gli aggiornamenti.",
       verification="curl -s https://SITO/ | grep -i 'generator'  e  curl -s https://SITO/feed/ | "
                    "grep -i generator  -> nessuna versione"),
    _T("wp.directory_listing", "Disattivare il directory listing",
       "Impedire al server di elencare il contenuto delle cartelle.",
       apache="Options -Indexes",
       nginx="Verificare che nel blocco server/location non ci sia 'autoindex on;' (il "
             "predefinito è off).",
       risks="Nessuno per WordPress: i file restano raggiungibili tramite il loro URL diretto.",
       verification="curl -s -o /dev/null -w '%{http_code}' https://SITO/wp-content/uploads/  -> 403 o 404"),
    _T("wp.debug_log", "Proteggere o rimuovere debug.log",
       "Disattivare il log su file in produzione o spostarlo fuori dalla web root.",
       wordpress="""wp-config.php:
define('WP_DEBUG', false);
define('WP_DEBUG_LOG', false);   // oppure un percorso fuori dalla web root:
// define('WP_DEBUG_LOG', '/var/log/wordpress/debug.log');
Poi cancellare wp-content/debug.log dopo averne salvato una copia se serve.""",
       apache="""<Files debug.log>
    Require all denied
</Files>""",
       nginx="location ~* /debug\\.log$ { deny all; }",
       risks="Nessuno. Verificare prima se il log contiene dati da segnalare (data breach).",
       verification="curl -s -o /dev/null -w '%{http_code}' https://SITO/wp-content/debug.log -> 403 o 404"),
    _T("http.headers", "Aggiungere gli header di sicurezza",
       "Configurare gli header a livello di server web (o con un plugin).",
       apache="""Verifica prima che il sito non abbia sottodomini senza HTTPS: HSTS parte con un
valore basso e si alza dopo i test.

<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=300"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "geolocation=(), camera=(), microphone=()"
</IfModule>""",
       nginx="""add_header Strict-Transport-Security "max-age=300" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;""",
       wordpress="CSP: va costruito in base alle risorse usate dal sito; provarlo prima con "
                 "Content-Security-Policy-Report-Only per non rompere pagine e plugin.",
       risks="HSTS con max-age alto rende il sito irraggiungibile in HTTP per tutta la durata: "
             "aumentarlo (fino a 31536000) solo dopo aver verificato HTTPS ovunque. Un CSP "
             "troppo restrittivo blocca script di plugin, analytics e pagamenti.",
       verification="curl -sI https://SITO/ | grep -iE 'strict-transport|content-security|"
                    "x-frame|x-content-type|referrer-policy|permissions-policy'"),
    _T("http.info_disclosure", "Ridurre le informazioni negli header",
       "Non esporre versioni di server e linguaggio.",
       apache="ServerTokens Prod\nServerSignature Off\n# php.ini: expose_php = Off",
       nginx="server_tokens off;\n# php.ini: expose_php = Off",
       risks="Nessuno.",
       verification="curl -sI https://SITO/ | grep -iE '^(server|x-powered-by):'  -> nessun numero di versione"),
    _T("http.cookies", "Attributi di sicurezza dei cookie",
       "Impostare Secure, HttpOnly e SameSite sui cookie del sito.",
       wordpress="I cookie di autenticazione di WordPress hanno già HttpOnly; quelli segnalati "
                 "vengono di solito da plugin o temi: aggiornare o configurare il plugin che li crea.",
       apache="Header always edit Set-Cookie ^(.*)$ \"$1; Secure; HttpOnly; SameSite=Lax\"",
       nginx="proxy_cookie_flags ~ secure httponly samesite=lax;  # nginx >= 1.19.3",
       risks="HttpOnly rompe i cookie che devono essere letti da JavaScript (es. consenso cookie).",
       verification="curl -sI https://SITO/ | grep -i set-cookie"),
    _T("http.https_redirect", "Reindirizzare HTTP a HTTPS",
       "Ogni richiesta in chiaro deve ricevere un redirect permanente a HTTPS.",
       apache="""RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]""",
       nginx="server { listen 80; server_name SITO; return 301 https://$host$request_uri; }",
       wordpress="In Impostazioni > Generali usare https:// sia per l'indirizzo WordPress sia "
                 "per l'indirizzo del sito.",
       risks="Contenuti misti (immagini o script in http://) vanno aggiornati.",
       verification="curl -sI http://SITO/ | head -3  -> 301 verso https://"),
    _T("tls.certificate", "Rinnovare o correggere il certificato",
       "Usare un certificato valido per tutti i nomi del sito, con rinnovo automatico.",
       wordpress="Con hosting condiviso: attivare il certificato gratuito (Let's Encrypt) dal pannello.",
       apache="certbot --apache -d SITO -d www.SITO",
       nginx="certbot --nginx -d SITO -d www.SITO",
       risks="Nessuno.",
       verification="echo | openssl s_client -connect SITO:443 -servername SITO 2>/dev/null | "
                    "openssl x509 -noout -dates -subject"),
    _T("tls.protocol", "Disattivare i protocolli TLS obsoleti",
       "Consentire solo TLS 1.2 e 1.3.",
       apache="SSLProtocol -all +TLSv1.2 +TLSv1.3",
       nginx="ssl_protocols TLSv1.2 TLSv1.3;",
       risks="Client molto vecchi (Android < 4.4, Windows XP) non potranno collegarsi.",
       verification="openssl s_client -connect SITO:443 -tls1_1  -> deve fallire",
       references=("https://ssl-config.mozilla.org/",)),
]

TEMPLATES: dict[str, RemediationTemplate] = {t.id: t for t in _TEMPLATES}
