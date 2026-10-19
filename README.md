# Spotify Anti-Pause

Block unwanted remote pauses in Spotify for Windows.

Supports **Spotify 1.3.5.3058 x64 (desktop)**. Targets one remote controller;
other causes of pausing aren't covered.

## Install

1. Download [SpotifyAntiPause.ps1](https://github.com/Maxhem2/spotify-anti-pause/releases/latest/download/SpotifyAntiPause.ps1).
2. Open PowerShell in the download folder and run:

```powershell
powershell -ExecutionPolicy Bypass -File .\SpotifyAntiPause.ps1
```

Restart Spotify using your usual shortcut.

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File .\SpotifyAntiPause.ps1 -Action Uninstall
```

Restart Spotify afterward.
