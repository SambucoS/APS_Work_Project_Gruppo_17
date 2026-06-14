# Sistema di Voto Elettronico — UNISA (WP4)

Questo progetto è l'implementazione di riferimento del protocollo di voto elettronico per il rinnovo del *Consiglio degli Studenti* dell'Università degli Studi di Salerno (liste chiuse).

Il documento completo del progetto è [`Project_Work_Completo.pdf`](Project_Work_Completo.pdf). La specifica tecnica `SPEC.md` citata nel codice è tenuta in locale e non è inclusa in questo repository: il PDF è il documento autorevole.

---

## Come funziona

Il protocollo si divide in sei fasi: autenticazione, invio del voto, acquisizione, scrutinio, verifica individuale e verifica universale. Ogni fase è implementata nel modulo corrispondente e la simulazione le esegue tutte in sequenza.

Per la crittografia si usa esclusivamente la libreria **`cryptography` (PyCA)** — niente implementazioni fatte in casa. L'unica eccezione è l'aritmetica di campo per il secret sharing di Shamir (aritmetica modulare big-int, come richiesto dalla specifica), che si appoggia a `secrets` per la generazione dei numeri casuali.

---

## Requisiti e installazione

Serve **Python 3.10 o superiore** (il codice usa le union type `X | Y` introdotte in 3.10) e la libreria `cryptography`. Nient'altro.

```bash
pip install cryptography
```

Se preferisci un ambiente virtuale isolato:

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Unix/Mac: source .venv/bin/activate
pip install cryptography
```

---

## Avviare la simulazione

Per eseguire la demo completa con 10 elettori (default):

```bash
python simulation.py
```

Per cambiare il numero di elettori:

```bash
python simulation.py --voters 50
```

La simulazione stampa l'avanzamento di ogni fase: setup e distribuzione delle chiavi, autenticazione + cifratura + acquisizione, re-autenticazione idempotente (stesso `token_id` deterministico) e rigetto dei replay, scrutinio (commit Merkle, ricostruzione Shamir, shuffle, decifratura, conteggio), verifica individuale (prova di inclusione Merkle) e verifica universale (il revisore ricalcola l'intera catena di hash, la radice Merkle, la cardinalità, il conteggio e le firme per token).

## Benchmark

```bash
python benchmarks.py
```

Misura (media su 10 esecuzioni via `time.perf_counter()`): tempo di keygen RSA-4096, cifratura OAEP e dimensione del ciphertext, sign/verify PSS e dimensione della firma, dimensione del B_packet e della ricevuta, tempo di costruzione dell'albero Merkle per N = 10/100/1000, tempo e dimensione della prova di inclusione, tempo del flusso completo per un singolo elettore, lookup anti-replay O(1). C'è anche una sezione di **scaling** che misura come il protocollo cresce al variare degli elettori (N = 100 / 1.000 / 10.000).

## Test dei singoli moduli

Ogni modulo ha i propri test unitari integrati. Puoi eseguirli singolarmente:

```bash
python crypto_utils.py
python pbb.py
python shamir.py
python as_server.py
python ea_server.py
python client.py
```

---

## Struttura del codice

| File | Cosa fa |
|---|---|
| [`crypto_utils.py`](crypto_utils.py) | Keygen RSA-4096, OAEP cifratura/decifratura, PSS firma/verifica, SHA-256, serializzazione PEM/DER — tutto tramite PyCA. |
| [`pbb.py`](pbb.py) | Public Bulletin Board: catena hash-pointer, albero di Merkle, prove di inclusione e verifica. |
| [`shamir.py`](shamir.py) | Secret sharing `(t, n)` di Shamir su GF(2¹²⁷−1) con interpolazione di Lagrange, applicato ai byte grezzi di SKEA. |
| [`as_server.py`](as_server.py) | Authentication Server: verifica dell'idoneità, emissione di un token con `token_id` HMAC deterministico (re-autenticazione idempotente), flag booleano di utilizzo per coppia (identità, elezione). |
| [`ea_server.py`](ea_server.py) | Electoral Authority: acquisizione del voto, verifica del token, anti-replay O(1), pipeline di scrutinio. |
| [`client.py`](client.py) | Client elettore: cifratura del voto, assemblaggio del B_packet, verifica della ricevuta e della prova di inclusione. |
| [`simulation.py`](simulation.py) | Demo end-to-end di tutte e sei le fasi. |
| [`benchmarks.py`](benchmarks.py) | Misurazioni di tempi e dimensioni dei messaggi. |

Il trasporto di rete (il "canale TLS") è **simulato come chiamate dirette tra funzioni**, come previsto dalla specifica — non c'è nessun server web o Flask.

---

## Scelte di design rilevanti

Alcune decisioni nel codice non sono ovvie, e vale la pena spiegarle:

- **L'AS conserva solo un flag booleano**, non il `token_id` ([`as_server.py`](as_server.py)). Con WP4 v2 il `token_id` è un HMAC deterministico dell'identità: anche se non viene salvato, chi possiede l'`hmac_secret` dell'AS può ricalcolarlo e collegare identità → voto. Questo rende la re-autenticazione idempotente e chiude la finestra temporale per il doppio voto, ma indebolisce la segretezza del voto in caso di collusione AS+EA — vedi la nota sulla privacy in `SPEC.md` §Token e `crypto_utils.derive_token_id`.
- **Il client non firma il B_packet** ([`client.py`](client.py)). L'autorizzazione è già garantita dal token firmato dall'AS; una firma del client introdurrebbe non-repudiabilità, aprendo la porta alla coercizione e al voto di scambio.
- **`salt_nonce` in ogni voto** ([`client.py`](client.py)), per prevenire attacchi a dizionario sullo spazio ristretto dei plaintext (3 liste).
- **Lo shuffle Fisher-Yates usa `secrets.randbelow`** ([`ea_server.py`](ea_server.py)), non `random`, per garantire casualità crittografica.
- **SKEA viene azzerata e cancellata** subito dopo la decifratura ([`ea_server.py`](ea_server.py)).

## Limitazioni note (non adatte alla produzione)

- **Il Shamir sui byte grezzi della chiave non è threshold RSA.** Spezzettare i byte di `SKEA` significa riassemblare l'intera chiave privata in un unico punto durante lo scrutinio — un singolo punto di compromissione. In produzione si userebbe **threshold RSA** (es. Shoup o FROST) in modo che la chiave non venga mai ricostruita per intero. Segnalato in [`shamir.py`](shamir.py) e [`ea_server.py`](ea_server.py).
- **La correttezza dello scrutinio è un'assunzione di fiducia.** Lo shuffle+decifratura non è provato corretto per ogni singolo voto; eliminarla richiederebbe un verifiable mix-net o una decifratura a soglia con prove ZK (WP2 §Trust Assumptions).
- **Le chiavi private sono salvate non cifrate** in `keys/`. In produzione andrebbero protette con passphrase e/o HSM.

---

## Fasi del protocollo (come implementate)

1. **Autenticazione** — l'AS verifica l'idoneità dell'elettore e rilascia un token firmato PSS con `token_id` HMAC deterministico (nessun campo `role`; re-autenticazione idempotente).
2. **Invio del voto** — il client costruisce `M` (con `salt_nonce`), cifra con OAEP sotto PKEA e assembla il B_packet.
3. **Acquisizione** — l'EA verifica firma/scadenza/election_id/scope del token, applica l'anti-replay O(1) sul `token_id`, appende il ciphertext al PBB con catena hash-pointer e restituisce una ricevuta PSS firmata sulla foglia Merkle.
4. **Scrutinio** — freeze, costruzione e firma della radice Merkle, ricostruzione di SKEA dalle `t` share di Shamir, shuffle Fisher-Yates, decifratura, validazione, pubblicazione del conteggio.
5. **Verifica individuale** — l'elettore controlla la firma della ricevuta e ricalcola la prova di inclusione Merkle rispetto alla radice firmata pubblicata.
6. **Verifica universale** — qualsiasi revisore può ricalcolare la catena hash-pointer, riderivare e verificare la firma della radice Merkle, riverificare la firma PSS (e l'`election_id`) su ogni token pubblicato sotto PKAS, verificare la cardinalità e ricontare i voti in chiaro pubblicati.

> **Nota sulla pubblicazione dei token (deviazione da `SPEC.md` §PBB Entry):** per rendere la fase 6.3 verificabile dal dump pubblico del PBB, ogni entry include anche il token firmato dall'AS. La formula dell'`entry_hash` resta invariata (`SHA-256(ciphertext || prev_hash)`); l'integrità del token è garantita dalla sua firma PSS.
>
> **Caveat privacy (WP4 v2):** pubblicare il token era sicuro con l'`token_id` UUID casuale originale. Con il **HMAC deterministico** di v2, chi ha l'`hmac_secret` dell'AS può ricalcolare il `token_id` di ogni elettore e abbinarlo ai token pubblicati, collegando identità → ciphertext. La segretezza del voto dipende ora dalla protezione di `hmac_secret` (idealmente HSM o threshold-shared) e dallo shuffle post-scrutinio. Vedi `SPEC.md` §Token.
