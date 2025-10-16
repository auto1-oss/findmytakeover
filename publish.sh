#!/bin/bash
set -e

# Upload Python package to Artifactory PyPI repository using twine
# Requires: ARTIFACTORY_ACCESS_TOKEN or ARTIFACTORY_USERNAME + ARTIFACTORY_PASSWORD

REPO_NAME="devops-artifacts"
PACKAGE_NAME="findmytakeover"
VERSION="2.0.0"
ARTIFACTORY_URL="https://artifactory.prod.auto1.team/artifactory"
# Correct PyPI upload URL for Artifactory
PYPI_URL="${ARTIFACTORY_URL}/api/pypi/${REPO_NAME}"

# Check for credentials
if [ -n "$ARTIFACTORY_ACCESS_TOKEN" ]; then
    USERNAME="admin"  # Can be any username when using token
    PASSWORD="$ARTIFACTORY_ACCESS_TOKEN"
elif [ -n "$ARTIFACTORY_USERNAME" ] && [ -n "$ARTIFACTORY_PASSWORD" ]; then
    USERNAME="$ARTIFACTORY_USERNAME"
    PASSWORD="$ARTIFACTORY_PASSWORD"
else
    echo "Error: Authentication required. Set one of:"
    echo "  - ARTIFACTORY_ACCESS_TOKEN"
    echo "  - ARTIFACTORY_USERNAME + ARTIFACTORY_PASSWORD"
    exit 1
fi

# Check if twine is installed
if ! command -v twine &> /dev/null; then
    echo "Installing twine..."
    pip install twine
fi

echo "Building package..."
python -m build

echo ""
echo "=========================================="
echo "Publishing to Artifactory PyPI Repository"
echo "=========================================="
echo "Repository: ${REPO_NAME}"
echo "Package: ${PACKAGE_NAME} v${VERSION}"
echo "URL: ${PYPI_URL}"
echo ""

# Upload using twine (proper PyPI protocol)
echo "📦 Uploading to Artifactory using twine..."
TWINE_USERNAME="$USERNAME" \
TWINE_PASSWORD="$PASSWORD" \
TWINE_REPOSITORY_URL="${PYPI_URL}" \
twine upload dist/* --verbose

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Successfully published ${PACKAGE_NAME} v${VERSION}"
else
    echo ""
    echo "❌ Failed to publish package"
    exit 1
fi

echo ""
echo "=========================================="
echo "Installation Instructions"
echo "=========================================="
echo ""
echo "1. Configure pip to use Artifactory:"
echo "   ./setup_pip.sh"
echo ""
echo "2. Install the package:"
echo "   pip install ${PACKAGE_NAME}"
echo ""
echo "3. Or install specific version:"
echo "   pip install ${PACKAGE_NAME}==${VERSION}"
echo ""
echo "4. Or use direct URL:"
echo "   pip install --index-url ${ARTIFACTORY_URL}/api/pypi/${REPO_NAME}/simple ${PACKAGE_NAME}"
echo ""
echo "Note: Package should be available via PyPI index immediately."
