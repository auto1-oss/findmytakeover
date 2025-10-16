#!/bin/bash
set -e

REPO="devops-artifacts"
PIP_CONFIG_DIR="${HOME}/.config/pip"
PIP_CONFIG_FILE="${PIP_CONFIG_DIR}/pip.conf"
PYPIRC_FILE="${HOME}/.pypirc"

echo "Setting up pip and twine for Artifactory..."

# Check credentials
USER="${ARTIFACTORY_USERNAME:-${ARTIFACTORY_USER}}"
PASS="${ARTIFACTORY_PASSWORD:-${ARTIFACTORY_ACCESS_TOKEN}}"

if [ -z "$USER" ] || [ -z "$PASS" ]; then
    echo "❌ Error: Set ARTIFACTORY_USERNAME and ARTIFACTORY_PASSWORD"
    echo ""
    echo "Add to ~/.zshrc:"
    echo '  export ARTIFACTORY_USERNAME="your-username"'
    echo '  export ARTIFACTORY_PASSWORD="your-token"'
    echo ""
    echo "Then: source ~/.zshrc && ./setup_pip.sh"
    exit 1
fi

# Create config dir
mkdir -p "$PIP_CONFIG_DIR"

# Backup existing
[ -f "$PIP_CONFIG_FILE" ] && cp "$PIP_CONFIG_FILE" "${PIP_CONFIG_FILE}.backup"
[ -f "$PYPIRC_FILE" ] && cp "$PYPIRC_FILE" "${PYPIRC_FILE}.backup"

# URL encode credentials
encode() {
    local string="${1}"
    local encoded=""
    local pos c
    for (( pos=0; pos<${#string}; pos++ )); do
        c=${string:$pos:1}
        case "$c" in
            [-_.~a-zA-Z0-9] ) encoded+="${c}" ;;
            * ) printf -v o '%%%02x' "'$c"; encoded+="$o" ;;
        esac
    done
    echo "$encoded"
}

ENC_USER=$(encode "$USER")
ENC_PASS=$(encode "$PASS")

# Generate pip.conf for installing packages
cat > "$PIP_CONFIG_FILE" << EOF
[global]
index-url = https://pypi.org/simple
extra-index-url = https://${ENC_USER}:${ENC_PASS}@artifactory.prod.auto1.team/artifactory/api/pypi/${REPO}/simple
timeout = 60

[install]
prefer-binary = true
EOF

chmod 600 "$PIP_CONFIG_FILE"

# Generate .pypirc for publishing packages with twine
cat > "$PYPIRC_FILE" << EOF
[distutils]
index-servers =
    artifactory

[artifactory]
repository = https://artifactory.prod.auto1.team/artifactory/api/pypi/${REPO}
username = ${USER}
password = ${PASS}
EOF

chmod 600 "$PYPIRC_FILE"

echo "✅ Configured pip: $PIP_CONFIG_FILE"
echo "✅ Configured twine: $PYPIRC_FILE"
echo ""
echo "Test: pip install --dry-run findmytakeover"
echo "Install: pip install findmytakeover"
echo "Publish: twine upload dist/*"
