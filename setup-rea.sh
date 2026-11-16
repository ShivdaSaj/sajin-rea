#!/bin/bash
# REA (morluto/rea): Node 24, npm 11, build, Ghidra 12.1.4, JADX MCP, Claude Code MCP registration.
set -euo pipefail
T=/opt/rea-tools
mkdir -p "$T"
if [ "$(/opt/node24/bin/node -v 2>/dev/null)" != "v24.22.1" ]; then
  f=node-v24.22.1-linux-x64.tar.xz
  curl -fsSL --retry 3 -o "/tmp/$f" "https://nodejs.org/dist/v24.22.1/$f"
  curl -fsSL https://nodejs.org/dist/v24.22.1/SHASUMS256.txt | grep " $f\$" | (cd /tmp && sha256sum -c -)
  rm -rf /opt/node24 && mkdir -p /opt/node24
  tar -xJf "/tmp/$f" -C /opt/node24 --strip-components=1 && rm "/tmp/$f"
fi
export PATH="/opt/node24/bin:$PATH"
[ "$(npm -v)" = "11.16.0" ] || npm install -g npm@11.16.0
J=jadx-headless-mcp-0.7.1-all.jar
if [ ! -f "$T/$J" ]; then
  curl -fsSL --retry 3 -o "$T/$J" "https://github.com/1013503897/jadx-headless-mcp/releases/download/v0.7.1/$J"
  echo "6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75  $T/$J" | sha256sum -c -
fi
G=ghidra_12.1.4_PUBLIC
if [ ! -d "$T/$G" ]; then
  curl -fsSL --retry 3 -o /tmp/ghidra.zip "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/${G}_20260921.zip"
  echo "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db  /tmp/ghidra.zip" | sha256sum -c -
  unzip -q /tmp/ghidra.zip -d "$T" && rm /tmp/ghidra.zip
fi
R=/opt/rea
[ -d "$R/.git" ] || git clone https://github.com/morluto/rea "$R"
C=4ea24b6f8e63081ec5077c8e88370a8632aeeb0c  # pinned REA commit
git -C "$R" cat-file -e "$C^{commit}" 2>/dev/null || git -C "$R" fetch -q origin "$C"
git -C "$R" checkout -q --detach "$C"
git -C "$R" submodule update --init --recursive --depth 50
(cd "$R" && npm ci && npm run build)
export GHIDRA_INSTALL_DIR="$T/$G" REA_JADX_MCP_JAR="$T/$J"
export JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")"
E=/etc/profile.d/rea.sh
{ echo 'export PATH="/opt/node24/bin:$PATH"'; echo "export GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR"
  echo "export REA_JADX_MCP_JAR=$REA_JADX_MCP_JAR"; echo "export JAVA_HOME=$JAVA_HOME"; } > "$E"
touch /root/.bashrc; grep -q "$E" /root/.bashrc 2>/dev/null || sed -i "1i . $E" /root/.bashrc
node "$R/scripts/rea.mjs" setup --client claude_code --yes > /dev/null || echo "rea setup needs review: run rea setup"
echo "REA $(node "$R/scripts/rea.mjs" --version) ready"
