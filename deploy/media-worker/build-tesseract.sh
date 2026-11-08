#!/bin/sh
set -eu
cd /build
python3.12 /build/ocr/fetch-sources.py
mkdir source
tar -xzf downloads/tesseract.tar.gz --strip-components=1 -C source
test "$(cat source/VERSION)" = '5.5.4'
cmake -S source -B tesseract-build \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib \
    -DPKG_CONFIG_ARGN=--static \
    -DBUILD_SHARED_LIBS=ON -DBUILD_TRAINING_TOOLS=OFF -DBUILD_TESTS=OFF \
    -DDISABLE_ARCHIVE=ON -DDISABLE_CURL=ON -DGRAPHICS_DISABLED=ON \
    -DENABLE_NATIVE=OFF -DENABLE_PRECOMPILED_HEADERS=OFF -DOPENMP_BUILD=OFF
cmake --build tesseract-build --parallel 2
DESTDIR=/build/stage cmake --install tesseract-build
mkdir -p package/usr/bin package/usr/lib package/usr/share/licenses/tesseract \
    package/usr/share/tesseract-ocr/5/tessdata package/usr/share/tgwitness-build/ocr /out
cp stage/usr/bin/tesseract package/usr/bin/
cp -a stage/usr/lib/libtesseract.so* package/usr/lib/
cp source/LICENSE package/usr/share/licenses/tesseract/LICENSE
cp downloads/tessdata.LICENSE package/usr/share/licenses/tesseract/tessdata.LICENSE
cp downloads/*.traineddata package/usr/share/tesseract-ocr/5/tessdata/
cp ocr/sources.lock.json package/usr/share/tgwitness-build/ocr/
python3.12 - <<'PY'
import hashlib
import json
from pathlib import Path
import stat

lock_path = Path('/build/ocr/sources.lock.json')
lock = json.loads(lock_path.read_text())
source = lock['tesseract']
package = Path('/build/package')
components = [{
    'SPDXID': 'SPDXRef-Tesseract', 'name': 'tesseract', 'versionInfo': source['version'],
    'downloadLocation': 'NONE', 'filesAnalyzed': True,
    'licenseConcluded': 'NOASSERTION', 'licenseDeclared': source['license'],
    'licenseInfoFromFiles': ['NOASSERTION'],
    'copyrightText': 'NOASSERTION',
    'sourceInfo': 'Built from ' + source['url'] + '; SHA256=' + source['sha256'] + '; commit=' + source['commit'],
    'externalRefs': [
        {'referenceCategory': 'SECURITY', 'referenceType': 'cpe23Type', 'referenceLocator': source['cpe']},
        {'referenceCategory': 'PACKAGE-MANAGER', 'referenceType': 'purl',
         'referenceLocator': 'pkg:generic/tesseract@' + source['version']},
    ],
}]
files = []
for index, path in enumerate(sorted(package.rglob('*'))):
    if path.is_file() and not path.is_symlink():
        content = path.read_bytes()
        files.append({'SPDXID': f'SPDXRef-File-{index}', 'fileName': './' + path.relative_to(package).as_posix(),
                      'checksums': [{'algorithm': 'SHA256', 'checksumValue': hashlib.sha256(content).hexdigest()},
                                    {'algorithm': 'SHA1', 'checksumValue': hashlib.sha1(content, usedforsecurity=False).hexdigest()}],
                      'licenseConcluded': 'NOASSERTION', 'licenseInfoInFiles': ['NOASSERTION'],
                      'copyrightText': 'NOASSERTION'})
file_sha1 = sorted(checksum['checksumValue'] for file in files for checksum in file['checksums']
                   if checksum['algorithm'] == 'SHA1')
components[0]['packageVerificationCode'] = {
    'packageVerificationCodeValue': hashlib.sha1(''.join(file_sha1).encode(), usedforsecurity=False).hexdigest(),
    'packageVerificationCodeExcludedFiles': ['./usr/share/tgwitness-build/ocr/tesseract.spdx.json'],
}
sbom = {
    'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0', 'SPDXID': 'SPDXRef-DOCUMENT',
    'name': 'TgWitness media worker Tesseract source and installed files',
    'documentNamespace': 'https://github.com/phishdestroy/TgWitness/spdx/tesseract-' + hashlib.sha256(
        lock_path.read_bytes() + json.dumps(files, sort_keys=True).encode()).hexdigest(),
    'creationInfo': {'creators': ['Tool: TgWitness container build'], 'created': '2026-11-02T00:00:00Z'},
    'packages': components, 'files': files,
    'relationships': [{'spdxElementId': 'SPDXRef-DOCUMENT', 'relationshipType': 'DESCRIBES',
                       'relatedSpdxElement': 'SPDXRef-Tesseract'}] + [
        {'spdxElementId': 'SPDXRef-Tesseract', 'relationshipType': 'CONTAINS', 'relatedSpdxElement': file['SPDXID']}
        for file in files
    ],
}
(package / 'usr/share/tgwitness-build/ocr/tesseract.spdx.json').write_text(json.dumps(sbom, indent=2) + '\n')
contents = []
for path in sorted(package.rglob('*')):
    destination = '/' + path.relative_to(package).as_posix()
    if path.is_symlink():
        contents.append({'src': path.readlink().as_posix(), 'dst': destination, 'type': 'symlink'})
    elif path.is_file():
        contents.append({'src': str(path), 'dst': destination,
                         'file_info': {'mode': stat.S_IMODE(path.stat().st_mode), 'owner': 'root', 'group': 'root'}})
config = Path('/build/ocr/tesseract.nfpm.yaml').read_text()
Path('/build/tesseract.nfpm.yaml').write_text(config + '\ncontents:\n' + ''.join(
    '  - ' + json.dumps(entry, sort_keys=True) + '\n' for entry in contents))
PY
case "$(apk --print-arch)" in x86_64) NFPM_ARCH=amd64 ;; aarch64) NFPM_ARCH=arm64 ;; *) exit 2 ;; esac
export NFPM_ARCH
openssl genrsa -out /build/tesseract-build.rsa 3072
openssl rsa -in /build/tesseract-build.rsa -pubout -out /out/tgwitness-tesseract-build.rsa.pub
nfpm package --packager apk --config /build/tesseract.nfpm.yaml --target /out/tesseract.apk
rm /build/tesseract-build.rsa
