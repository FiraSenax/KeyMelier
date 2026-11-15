# Projektleitlinien

## Extrem vorsichtig bei Breaking Changes

- Bestehende Daten, Einstellungen, Import-/Exportformate, öffentliche Schnittstellen,
  Update-Wege und unterstützte Plattformen müssen kompatibel bleiben.
- Kleine, gezielte Änderungen bevorzugen. Keine beiläufigen Umbenennungen,
  Formatwechsel, entfernten Optionen oder größeren Abhängigkeits-Upgrades.
- Vor einer möglichen Inkompatibilität die betroffenen Nutzer und Aufrufer prüfen.
  Erhalt der Kompatibilität oder eine rückwärtskompatible Erweiterung hat Vorrang.
- Ist eine inkompatible Änderung notwendig, etwa um eine bestätigte Sicherheitslücke
  zu schließen, Auswirkungen und Grund ausdrücklich benennen, einen sicheren
  Migrationsweg dokumentieren und die betroffenen Übergänge gezielt testen.
  Sicherheitsprüfungen nicht zugunsten unsicherer Altverhalten abschwächen.
- Vorhandene uncommittete Änderungen erhalten. Keine Daten oder Einstellungen
  stillschweigend löschen, zurücksetzen oder unlesbar machen.

## Projekt und Validierung

- KeyMelier ist eine Python-/pywebview-Desktop-App für macOS, Windows und Linux.
  Backend und Gerätezugriff liegen in `keymelier_core/`, die UI in `static/`.
- `.github/copilot-instructions.md` enthält Einrichtung und vorhandene
  Prüfkommandos. Die maßgeblichen CI-Schritte stehen in
  `.github/workflows/build.yml`; passende Prüfungen nach dem betroffenen Bereich
  auswählen und tatsächlich ausgeführte Prüfungen im PR nennen.
- Gerätezugriff in Tests simulieren. Ohne ausdrücklichen Auftrag keine echten
  PIN-Versuche, Schreibzugriffe, Resets oder Änderungen an persönlichen Daten,
  am Betriebssystem-Schlüsselbund oder an Signierzugängen ausführen.
- Quellcode-, Demo- und synthetische Tests belegen keine erfolgreiche Prüfung
  am echten Schlüssel oder im signierten Installationspaket. Offene Plattform-
  und Hardwareprüfungen in `HARDWARE_TESTS.md` korrekt offen lassen.

## Pull Requests und Reviews

- Bei bereits beauftragter PR-Arbeit ist CodeRabbit der Standard für Reviews.
  Copilot vor allem für Implementierung, Erklärung und Tests nutzen; ein
  zusätzliches Copilot-Code-Review nur auf ausdrücklichen Wunsch anfordern.
- Zusammengehörige Änderungen gebündelt pushen und Entwürfe während laufender
  Arbeit als Draft belassen. Für fertige PRs das vorhandene automatische
  CodeRabbit-Review abwarten; nicht parallel dieselbe Prüfung erneut anfordern.
- Wenn CodeRabbit ausdrücklich eine manuelle Anforderung verlangt oder nach
  einer Pause die letzten Änderungen noch ungeprüft sind, einmal
  `@coderabbitai review` als PR-Kommentar anfordern. Vorher laufende Reviews,
  bestehende Anfragen und den abgedeckten Commit prüfen. Kontingentgrenzen
  respektieren; keine Wiederholungsschleifen oder kostenpflichtigen Credits.
- Befunde auf Nachvollziehbarkeit prüfen, berechtigte Probleme gezielt beheben
  und betroffene Tests ausführen. Nach einem weiteren Push den Review-Stand
  für den aktuellen PR-Head prüfen; Zusammenfassungen allein sind kein Beleg
  für ein abgeschlossenes Review.
- CodeRabbit-Agent/Autofix, bezahlten Zusatzverbrauch und zusätzliche Abos
  nicht als Teil dieses Ablaufs aktivieren. Ein Review ersetzt weder CI noch
  erforderliche menschliche Freigaben und erteilt keinen Release-Auftrag.
- Die aktuellen CodeRabbit-Tarifgrenzen gelten unabhängig von den Einstellungen:
  öffentliche Repositories unter zehn Sternen benötigen laut Anbieter manuelle
  Review-Anfragen. Automatische Reviews daher nicht allein aufgrund eines
  aktivierten Schalters versprechen.
