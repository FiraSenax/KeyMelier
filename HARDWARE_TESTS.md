# Hardware-Testmatrix

Manuelle Tests mit echten Sicherheitsschlüsseln. Automatische Prüfungen
stehen in [TESTING.md](TESTING.md); was dort nicht geht (echte Schlüssel,
Abziehen, PIN-Eingabe), wird hier festgehalten.

**Regeln**

- Ergebnis immer eines von: **Bestanden**, **Fehlgeschlagen**,
  **Nicht unterstützt** (der Schlüssel kann es nicht), **Nicht getestet**.
- Keine Ergebnisse eintragen, die nicht selbst beobachtet wurden.
- Keine Seriennummern, Kontonamen, PINs oder andere persönliche Daten.
  Nur Modell, Firmware und das beobachtete Verhalten.
- Nur Test- oder Zweitschlüssel verwenden. Nichts zurücksetzen, keine
  Credentials löschen, keine PIN ändern – außer der Test verlangt es
  ausdrücklich und der Schlüssel ist ein Testschlüssel.

## Ablauf je Zeile

1. **Erkennung:** Schlüssel anstecken. Erscheint er in der Seitenleiste mit
   Modell und Firmware? Echtheitsprüfung (ggf. berühren)?
2. **Auslesefunktionen:** *Schlüssel auslesen* (PIN eingeben). Welche
   Bereiche werden gelesen – Passkeys (Liste bzw. Suche bei FIDO 2.0),
   Authenticator (OATH), OpenPGP, PIV, OTP-Slots? Nicht vorhandene
   Anwendungen als *Nicht unterstützt*.
3. **Abbruch und erneutes Verbinden:**
   a) PIN-Dialog öffnen und mit *Abbrechen*/Esc schließen – es darf kein
      PIN-Versuch verbraucht werden (Zähler im PIN-Tab prüfen).
   b) Während *Schlüssel auslesen* den Schlüssel abziehen – erwartet:
      Fehlermeldung „wurde beim Auslesen abgezogen“, bekannte Daten bleiben.
   c) Wieder anstecken, erneut auslesen – erwartet: funktioniert.
   d) Bei FIDO-2.0-Schlüsseln: Passkey-Suche starten und *Stoppen* – bereits
      gefundene Einträge bleiben, „nicht abgefragt“ bleibt unbekannt.
4. **Ergebnis** und Auffälligkeiten mit Datum eintragen.

## Matrix

| Betriebssystem + Version | KeyMelier (Version/Commit) | Schlüsselmodell | Firmware | Erkennung | Auslesefunktionen | Abbruch + erneutes Verbinden | Ergebnis | Datum, Anmerkungen |
|---|---|---|---|---|---|---|---|---|
| Windows (Version nicht erfasst) | 1.5.0 | nicht erfasst | nicht erfasst | Bestanden | Nicht getestet | Nicht getestet | Bestanden (nur Installation und Start) | 2026-09-27 – vom Projektinhaber gemeldet: „Windows läuft, getestet mit Installer“. Keine Details zu Schlüssel und Funktionen erfasst. |
| macOS + Windows (Versionen nicht erfasst) | 1.6.0 | – | – | – | – | – | Bestanden (Sync zwischen zwei Rechnern) | 2026-09-27 – vom Projektinhaber gemeldet: Sync Mac ↔ Windows eingerichtet, Abgleich funktioniert („sync sieht gut aus“). Kein Schlüsseltest. |
| macOS (Version nicht erfasst) | Entwicklungsstand 1.3.1 | YubiKey mit FIDO 2.0 (Anzeige „YubiKey OTP+FIDO+CCID“) | nicht erfasst | Bestanden | Passkey-Suche: Bestanden (70 Seiten abgefragt, 4 mit Passkeys gefunden) | Nicht getestet | Bestanden (Suche) | 2026-09 – Diagnoselauf während der Entwicklung (lokales Protokoll). Version der App nicht mehr eindeutig; nur als Hinweis. |
| macOS 14/15 | 1.7.0 oder neuer | YubiKey 5 (FW 5.7) | | Nicht getestet | Nicht getestet | Nicht getestet | Nicht getestet | |
| macOS 14/15 | 1.7.0 oder neuer | YubiKey 5 (FW 5.1/5.2, FIDO 2.0) | | Nicht getestet | Nicht getestet | Nicht getestet | Nicht getestet | Passkeys nur per Suche |
| macOS 14/15 | 1.7.0 oder neuer | YubiKey Bio | | Nicht getestet | Nicht getestet | Nicht getestet | Nicht getestet | Fingerabdruck statt PIN prüfen |
| macOS 14/15 | 1.7.0 oder neuer | Token2 (PIN+ / FIDO2.1) | | Nicht getestet | Nicht getestet | Nicht getestet | Nicht getestet | |
| macOS 14/15 | 1.7.0 oder neuer | Feitian (ePass/BioPass) | | Nicht getestet | Nicht getestet | Nicht getestet | Nicht getestet | |
| Windows 11 | 1.7.0 oder neuer | YubiKey 5 (FW 5.7) | | Nicht getestet | Nicht getestet | Nicht getestet | Nicht getestet | App startet mit Adminrechten |
| Windows 11 | 1.7.0 oder neuer | YubiKey 5 (FW 5.1/5.2, FIDO 2.0) | | Nicht getestet | Nicht getestet | Nicht getestet | Nicht getestet | |
| Windows 11 | 1.7.0 oder neuer | Token2 (PIN+ / FIDO2.1) | | Nicht getestet | Nicht getestet | Nicht getestet | Nicht getestet | |
| Windows 10 | 1.7.0 oder neuer | beliebiger FIDO2-Schlüssel | | Nicht getestet | Nicht getestet | Nicht getestet | Nicht getestet | |

Offene Kombinationen sind alle Zeilen mit **Nicht getestet**. Neue Zeilen
für weitere Modelle einfach anhängen; bei einem Update-Test in
*Anmerkungen* „Update von x.y“ vermerken (Ablauf in TESTING.md).
