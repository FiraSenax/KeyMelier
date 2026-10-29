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
