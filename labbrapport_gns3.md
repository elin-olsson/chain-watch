# Labbrapport — GNS3-test av chain-watch
**Datum:** 2026-04-24  
**Utfört av:** Elin Olsson

---

## Syfte

Syftet med labben var att verifiera att chain-watch fungerar mot riktig attacktrafik i en kontrollerad nätverksmiljö, innan verktyget publicerades offentligt på GitHub. Testet skulle bekräfta att journald-parsern, tidsfiltrering och kedjekorrelation fungerar korrekt — inte bara mot syntetiska testdata utan mot verkliga SSH-attacker.

---

## Labbmiljö

Labben byggdes i GNS3 med tre noder kopplade via en virtuell switch:

| Nod | OS | IP | Roll |
|---|---|---|---|
| Kali | Kali Linux | 192.168.100.99 | Angripare |
| Target | Debian 12 (GNS3) | 192.168.100.10 | Mål |
| Server | Debian 12 (GNS3) | 192.168.100.20 | Analysmaskin |

Laptop (192.168.122.x via NAT-nod) användes för att överföra filer till noderna med `scp`.

---

## Förberedelser

### Target
Installerades och konfigurerades med:
```bash
sudo apt update
sudo apt install -y openssh-server ufw auditd
sudo systemctl enable --now ssh auditd
sudo ufw enable
```

Testkonto skapades:
```bash
sudo useradd -m testuser
echo "testuser:princess" | sudo chpasswd
```

### Verktyget
chainwatch.py kopierades från laptop till Target via scp:
```bash
scp chainwatch.py debian@192.168.100.10:/home/debian/
```

---

## Utförande

### Test 1 — brute_force mot root

Hydra startades på Kali mot Target med rockyou.txt:
```bash
sudo hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.100.10 ssh -t 4 -V
```

chain-watch kördes på Target:
```bash
sudo python3 /home/debian/chainwatch.py --journal --since 13:42
```

**Resultat:** 445 misslyckade inloggningar från 192.168.100.99 detekterades. `brute_force [MEDIUM]` triggades korrekt.

---

### Test 2 — brute_then_login mot testuser

Hydra kördes mot testuser med lösenordet "princess" (position ~6 i rockyou.txt):
```bash
sudo hydra -l testuser -P /usr/share/wordlists/rockyou.txt 192.168.100.10 ssh -t 4 -V
```

Hydra hittade lösenordet på försök 6. chain-watch kördes:
```bash
sudo python3 /home/debian/chainwatch.py --journal --since 16:00
```

**Resultat (före fix):** Endast `brute_force [MEDIUM]` detekterades trots att inloggningen lyckades.

---

## Felsökning

### Problem: brute_then_login triggades inte

Journalen bekräftade att den lyckade inloggningen fanns:
```bash
sudo journalctl -u ssh --since "16:00" | grep -i "accepted"
# Apr 24 16:02:43 debian sshd[3347]: Accepted password for testuser from 192.168.100.99 port 55994 ssh2
```

**Rotorsak:** Korrelationslogiken i `chainwatch.py` (rad 672) krävde att `successful_login` inträffade **efter** klustrets sista `failed_login`:
```python
if cluster_end <= e["timestamp"] <= cluster_end + window
```

Men hydras fyra parallella uppkopplingar (-t 4) loggade den lyckade inloggningen (16:02:43) en sekund **innan** de sista misslyckade försöken avslutades (16:02:44). Villkoret `cluster_end <= timestamp` misslyckas i detta fall.

**Fix:** Villkoret ändrades till att acceptera lyckad inloggning från klustrets start:
```python
if t0 <= e["timestamp"] <= cluster_end + window
```

---

### Problem: Felaktig tidszon i --since

Target kör UTC, laptopen kör CEST (UTC+2). Kali kör utan tidssynkronisering och visade ca 6 timmar fel tid. Det krävde att Target-tid alltid användes i `--since`-flaggan, inte lokal tid.

**Lösning:** Kontrollera alltid `date` på Target innan `--since` anges.

---

### Problem: Diskfull på Target

`chpasswd` returnerade *"authentication token manipulation error"* när lösenord skulle ändras. Undersökning visade att auditd-loggen vuxit sig stor under hydras långa körning.

**Lösning:**
```bash
sudo truncate -s 0 /var/log/audit/audit.log
```

---

## Resultat efter fix

```
[CRITICAL]  #1  brute_then_login  —  192.168.100.99
2026-04-24  16:00:00  →  16:02:43  (2m 42s)  ·  150 events

  16:00:00  failed_login      user=testuser    ip=192.168.100.99
  ...
  16:02:43  successful_login  user=testuser    ip=192.168.100.99
```

Kedjan `brute_then_login [CRITICAL]` detekterades korrekt efter bugfixen.

---

## Slutsats

chain-watch detekterar SSH-brute force-attacker i realtid från systemd journal utan att kräva traditionella loggfiler (`/var/log/auth.log`). Labben bekräftade att:

1. Journald-parsern fungerar mot riktig SSH-trafik
2. `brute_force`-kedjan detekterar massiva lösenordsattacker korrekt
3. `brute_then_login`-kedjan kräver korrekt korrelation — en bugg hittades och fixades tack vare labbtestning mot verklig trafik (något enhetstester inte fångade)
4. Verktyget hanterar tidszonsskillnader korrekt om `--since` anges i systemnativ tid

Buggfixen släpptes som v1.2.1.
