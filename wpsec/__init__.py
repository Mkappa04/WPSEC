"""wpsec: piattaforma multi-agente di Web Vulnerability Assessment per WordPress.

Evoluzione dello scanner v3 (Pentest_ollama_v2.py, agente.py). Principio guida:
il codice decide cosa si fa (richieste, controlli, conferme), l'IA locale spiega
e contestualizza, ma non può inviare richieste né confermare risultati senza prove.
"""

__version__ = "4.0.0"
