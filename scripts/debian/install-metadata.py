#!/usr/bin/python3
"""Relocate compression development metadata without retaining staging paths."""
from pathlib import Path
import shutil
import sys

stage, package, libdir = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
private = f"{libdir}/kae"
pkgconfig = package / libdir.lstrip("/") / "pkgconfig"
for name, version, library in (
    ("zlib", "1.2.11", "z"),
    ("zstd", "1.5.4", "zstd"),
    ("lz4", "1.9.4", "lz4"),
    ("snappy", "1.1.10", "snappy"),
):
    (pkgconfig / f"kae-{name}.pc").write_text(
        f"prefix=/usr\nlibdir={private}\nincludedir=/usr/include/kae/{name}\n\n"
        f"Name: kae-{name}\nDescription: KAE accelerated {name}\nVersion: {version}\n"
        f"Libs: -L${{libdir}} -Wl,-rpath,${{libdir}} -l{library}\n"
        "Cflags: -I${includedir}\n"
    )

cmake = stage / "kaesnappy/lib/cmake"
if cmake.is_dir():
    dest = package / private.lstrip("/") / "cmake"
    shutil.copytree(cmake, dest)
    for file in dest.rglob("*.cmake"):
        data = file.read_text()
        data = data.replace("${_IMPORT_PREFIX}/lib/", f"{private}/")
        data = data.replace("${_IMPORT_PREFIX}/include", "/usr/include/kae/snappy")
        data = data.replace(str(stage / "kaesnappy/lib"), private)
        data = data.replace(str(stage / "kaesnappy/include"), "/usr/include/kae/snappy")
        if str(stage.parent) in data:
            raise SystemExit(f"unrelocated build path in {file}")
        file.write_text(data)
