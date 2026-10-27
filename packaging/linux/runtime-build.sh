#!/bin/sh
# Executed in a pinned Alpine container with networking disabled. All archives
# were checked by build_runtime.py; the complete recipe is shipped with sources.
set -eu
mkdir -p /tmp/runtime-build
cd /tmp/runtime-build
for archive in /sources/*; do tar xf "$archive"; done
export CFLAGS='-ffunction-sections -fdata-sections -Os'
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/lib/pkgconfig
cd zlib-*
./configure --static --prefix=/usr/local
make -j4
make install
cd ../zstd-*
make -C lib -j4 libzstd.a
make -C lib PREFIX=/usr/local install-static install-includes install-pc
cd ../mimalloc-*
cmake -S . -B out -DMI_BUILD_SHARED=OFF -DMI_BUILD_OBJECT=OFF -DMI_BUILD_TESTS=OFF -DMI_BUILD_STATIC=ON
cmake --build out -j4
cmake --install out
cp out/libmimalloc.a /usr/local/lib/libmimalloc.a
cd ../fuse-*
patch -p1 -i ../type2-runtime-*/patches/libfuse/mount.c.diff
meson setup out --prefix=/usr --default-library=static -Dexamples=false -Dtests=false
meson compile -C out -j4
meson install -C out
cd ../squashfuse-*
./autogen.sh
./configure --disable-shared --enable-static --without-xz --without-lzo --without-lz4 LDFLAGS=-static
make -j4
make install
mkdir -p /usr/local/include/squashfuse
cp ./*.h /usr/local/include/squashfuse/
cd ../type2-runtime-*/src/runtime
printf '%s\n' "$RUNTIME_COMMIT-keymelier" > version
make runtime LIBS='-L/usr/local/lib -Wl,-Map=/out/runtime.map -lsquashfuse -lsquashfuse_ll -lzstd -lz -lfuse3 -lmimalloc'
cp runtime /out/runtime-unstripped
strip --strip-debug --strip-unneeded runtime
printf 'AI\002' | dd of=runtime bs=1 count=3 seek=8 conv=notrunc
cp runtime /out/runtime
readelf -d runtime > /out/elf-dynamic.txt
apk info -v > /out/alpine-packages.txt
cp /lib/apk/db/installed /out/alpine-installed.txt
python3 - <<'PY'
import hashlib,json,re,subprocess
from pathlib import Path
files={p for p in re.findall(r'(/[^\s()]+\.(?:a|o))',Path('/out/runtime.map').read_text())}
records=[]
for filename in sorted(files):
    path=Path(filename).resolve()
    if path.is_file():
        records.append({'file':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
Path('/out/linked-files.json').write_text(json.dumps(records,indent=2)+'\n')
packages={'zlib':'zlib','zstd':'libzstd','mimalloc':'mimalloc','libfuse':'fuse3','squashfuse':'squashfuse'}
versions={name:subprocess.check_output(['pkg-config','--modversion',package],text=True).strip()
          for name,package in packages.items()}
# mimalloc's .pc file records only major.minor. Ask the actual static library
# for its complete version instead of reporting a guessed patch release.
Path('/tmp/mi-version.c').write_text('#include <stdio.h>\nextern int mi_version(void);\nint main(void) { printf("%d", mi_version()); return 0; }\n')
subprocess.run(['cc','/tmp/mi-version.c','/usr/local/lib/libmimalloc.a','-pthread','-o','/tmp/mi-version'],check=True)
number=int(subprocess.check_output(['/tmp/mi-version'],text=True))
versions['mimalloc']=f'{number//100}.{number//10%10}.{number%10}'
Path('/out/component-versions.json').write_text(json.dumps(versions,indent=2)+'\n')
PY
