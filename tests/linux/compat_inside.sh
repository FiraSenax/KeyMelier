#!/bin/bash
# Runs INSIDE a clean distribution container (see tools/linux_compat.py):
# install only the documented runtime prerequisites (docs/guide.html#linux)
# plus the test harness, record the AppImage's SHA-256, list host libraries it
# cannot find, then run the packaged start test under Xvfb with a D-Bus
# session and an unlocked Secret Service. Writes /out/result.json.
#
#   compat_inside.sh APPIMAGE MODE      MODE: native | emulated
set -uo pipefail
APPIMAGE="$1"; MODE="${2:-native}"; OUT=/out
. /etc/os-release
# The container runs as root; hand the results back to the calling user
# (Linux CI runners map the uid 1:1), however the script ends
trap '[ -n "${HOST_UID:-}" ] && chown -R "$HOST_UID:${HOST_GID:-$HOST_UID}" "$OUT"' EXIT
LOG="$OUT/install.log"

# Runtime prerequisites: the libraries the AppImage takes from the system
# (display server, graphics driver, fonts, sound, D-Bus) – what a desktop
# installation already has. Keep in sync with docs/guide.html#linux.
case "$ID" in
  ubuntu|debian)
    RUNTIME="libx11-6 libx11-xcb1 libxcb1 libxext6 libxfixes3 libxi6 libxrender1 libxrandr2 libxcursor1
      libxinerama1 libxcomposite1 libxdamage1 libxtst6 libsm6 libice6 libgl1 libegl1 libopengl0 libgbm1 libdrm2
      libfontconfig1 libfreetype6 libharfbuzz0b fonts-dejavu-core libdbus-1-3 libasound2t64 libglib2.0-0t64
      libwayland-client0 libwayland-cursor0 libwayland-egl1 libudev1"
    HARNESS="python3 xvfb xauth dbus dbus-user-session gnome-keyring squashfs-tools ca-certificates"
    install() { apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends $RUNTIME $HARNESS; } ;;
  fedora)
    RUNTIME="libX11 libX11-xcb libxcb libXext libXfixes libXi libXrender libXrandr libXcursor libXinerama
      libXcomposite libXdamage libXtst libSM libICE libglvnd-glx libglvnd-egl libglvnd-opengl mesa-libgbm libdrm
      fontconfig freetype harfbuzz dejavu-sans-fonts dbus-libs alsa-lib glib2 libwayland-client libwayland-cursor
      libwayland-egl systemd-libs"
    HARNESS="python3 xorg-x11-server-Xvfb xorg-x11-xauth dbus-daemon gnome-keyring squashfs-tools shadow-utils util-linux"
    install() { dnf install -y -q --setopt=install_weak_deps=False $RUNTIME $HARNESS; } ;;
  opensuse-leap|opensuse-tumbleweed)
    RUNTIME="libX11-6 libX11-xcb1 libxcb1 libXext6 libXfixes3 libXi6 libXrender1 libXrandr2 libXcursor1
      libXinerama1 libXcomposite1 libXdamage1 libXtst6 libSM6 libICE6 Mesa-libGL1 Mesa-libEGL1 libglvnd libgbm1 libdrm2
      fontconfig libfreetype6 libharfbuzz0 dejavu-fonts libdbus-1-3 libasound2 libglib-2_0-0 libwayland-client0
      libwayland-cursor0 libwayland-egl1 libudev1"
    HARNESS="python3 xvfb-run xorg-x11-server-Xvfb xauth dbus-1 dbus-1-daemon gnome-keyring squashfs shadow util-linux"
    install() { zypper -n -q install --no-recommends $RUNTIME $HARNESS; } ;;
  arch)
    RUNTIME="libx11 libxcb libxext libxfixes libxi libxrender libxrandr libxcursor libxinerama libxcomposite
      libxdamage libxtst libsm libice libglvnd mesa libdrm fontconfig freetype2 harfbuzz ttf-dejavu dbus alsa-lib
      glib2 wayland systemd-libs"
    HARNESS="python xorg-server-xvfb xorg-xauth gnome-keyring squashfs-tools"
    # pacman's download sandbox cannot set up seccomp under QEMU emulation; only
    # then (inside this throwaway container) retry without it
    install() { pacman -Syu --noconfirm --needed $RUNTIME $HARNESS ||
                { [ "$MODE" = emulated ] && pacman -Syu --noconfirm --needed --disable-sandbox $RUNTIME $HARNESS; }; } ;;
  *) echo "unsupported distribution $ID"; exit 2 ;;
esac

result() {   # status detail
  python3 - "$@" <<'PY' 2>/dev/null || printf '{"status": "%s", "detail": "%s", "sha256": "%s", "mode": "%s", "arch": "%s", "id": "%s", "version_id": "%s", "run_id": "%s"}\n' \
      "$1" "$2" "$(cut -d' ' -f1 /out/sha256.txt 2>/dev/null)" "$MODE" "$(uname -m)" "$ID" "${VERSION_ID:-}" "${RUN_ID:-}" > /out/result.json
import json, os, sys
status, detail = sys.argv[1], sys.argv[2]
def read(name, default=""):
    try:
        return open(os.path.join("/out", name), encoding="utf-8").read().strip()
    except OSError:
        return default
os_release = dict(l.split("=", 1) for l in open("/etc/os-release").read().splitlines() if "=" in l)
smoke = {}
try:
    smoke = json.load(open("/out/smoke/self-test.json"))
except Exception:
    pass
json.dump({"distribution": os_release.get("PRETTY_NAME", "").strip('"'), "id": os_release.get("ID", "").strip('"'),
           "version_id": os_release.get("VERSION_ID", "").strip('"'), "arch": os.uname().machine,
           "mode": os.environ.get("MODE"), "appimage": os.path.basename(os.environ.get("APPIMAGE", "")),
           "run_id": os.environ.get("RUN_ID", ""),
           "sha256": read("sha256.txt").split(" ")[0], "glibc": read("glibc.txt"),
           "missing_required": [l for l in read("missing-required.txt").splitlines() if l],
           "missing_optional": [l for l in read("missing-optional.txt").splitlines() if l],
           "checks": len(smoke.get("checks", [])), "passed_checks": sum(1 for c in smoke.get("checks", []) if c.get("ok")),
           "status": status, "detail": detail}, open("/out/result.json", "w"), indent=1)
PY
}
export MODE APPIMAGE

# 1. Which package exactly is tested (before anything runs)
sha256sum "$APPIMAGE" > "$OUT/sha256.txt"
# Package mirrors fail now and then: up to three attempts. Still failing
# means no evidence for this distribution – the test fails.
installed=no
for attempt in 1 2 3; do
  if install >> "$LOG" 2>&1; then installed=yes; break; fi
  echo "install attempt $attempt failed" | tee -a "$LOG"
  [ $attempt -lt 3 ] && sleep $((attempt * 20))
done
if [ $installed = no ]; then
  tail -20 "$LOG"; result failed "installing the runtime prerequisites failed 3 times (see install.log)"; exit 1
fi
ldd --version 2>&1 | head -1 > "$OUT/glibc.txt"

# 2. Unpack (read-only copy) to list libraries the host does not provide.
#    Required: the program, every bundled library, Qt WebEngine's helper and the
#    display plugins a desktop uses (xcb = X11, wayland). Optional: all other
#    plugins – e.g. the GTK theme without GTK, or the eglfs/linuxfb/vnc/offscreen
#    platforms that only run without a desktop; Qt skips those that cannot load.
WORK=$(mktemp -d)
OFFSET=$(python3 -c "import sys; sys.path.insert(0, '/src/tools'); import check_artifacts as c; print(c.appimage_offset(open('$APPIMAGE', 'rb').read(4 << 20)))")
unsquashfs -q -o "$OFFSET" -d "$WORK/root" "$APPIMAGE" > /dev/null
INTERNAL="$WORK/root/usr/lib/keymelier/_internal"
export LD_LIBRARY_PATH="$INTERNAL:$INTERNAL/PySide6/Qt/lib"
scan() { for f in "$@"; do ldd "$f" 2>/dev/null | awk -v f="${f#$WORK/root/}" '/not found/ {print $1 " (needed by " f ")"}'; done | sort -u; }
scan "$WORK/root/usr/lib/keymelier/KeyMelier" $(find "$INTERNAL" -maxdepth 1 -name '*.so*') \
     $(find "$INTERNAL/PySide6" -maxdepth 1 -name '*.so*') $(find "$INTERNAL/PySide6/Qt/lib" -name '*.so*') \
     "$INTERNAL/PySide6/Qt/libexec/QtWebEngineProcess" \
     $(find "$INTERNAL/PySide6/Qt/plugins/platforms" \( -name 'libqxcb.so' -o -name 'libqwayland*.so' \)) \
     > "$OUT/missing-required.txt"
scan $(find "$INTERNAL/PySide6/Qt/plugins" -name '*.so' -not -name 'libqxcb.so' -not -name 'libqwayland*.so') \
     > "$OUT/missing-optional.txt"
[ -s "$OUT/missing-required.txt" ] && { echo "Required host libraries missing:"; cat "$OUT/missing-required.txt"; }
[ -s "$OUT/missing-optional.txt" ] && { echo "Optional (plugins that will not load):"; cat "$OUT/missing-optional.txt"; }
unset LD_LIBRARY_PATH

# 3. The start test, as a normal user, with a virtual display, D-Bus and keyring
id tester > /dev/null 2>&1 || useradd -m tester
mkdir -p "$OUT/smoke" && chown -R tester "$OUT/smoke"
if [ "$MODE" = emulated ]; then
  # Under CPU emulation the AppImage runtime cannot be executed (binfmt); run
  # the unpacked copy of the same file instead – reported as such
  chown -R tester "$WORK" && chmod 755 "$WORK"
  TARGET="$WORK/root/AppRun"
else
  cp "$APPIMAGE" /home/tester/KeyMelier.AppImage && chmod 755 /home/tester/KeyMelier.AppImage
  TARGET=/home/tester/KeyMelier.AppImage
fi
cp -r /src/tools /home/tester/tools && chown -R tester /home/tester
su tester -c "cd /home/tester && export SMOKE_ARTIFACTS=$OUT/smoke SMOKE_TIMEOUT=${SMOKE_TIMEOUT:-300} DISPLAY=:99
  Xvfb :99 -screen 0 1400x900x24 -nolisten tcp > /tmp/xvfb.log 2>&1 &
  sleep 2
  dbus-run-session -- bash -c 'echo -n test | gnome-keyring-daemon --unlock --components=secrets > /dev/null 2>&1;
    python3 tools/smoke_packaged.py $TARGET'" > "$OUT/smoke.log" 2>&1
CODE=$?
cat "$OUT/smoke.log" | grep -v '^ok ' | tail -5
# A successful start never outweighs a missing required library
if [ -s "$OUT/missing-required.txt" ]; then
  result failed "required host libraries missing (see missing-required.txt)"
  exit 1
elif [ $CODE -eq 0 ]; then
  result passed "packaged start test passed"
else
  result failed "packaged start test failed (exit $CODE, see smoke.log and smoke/)"
fi
exit $CODE
