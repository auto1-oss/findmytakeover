# Quick Setup

## First Time Setup

```bash
# 1. Add credentials to shell profile
cat >> ~/.zshrc << 'CREDS'
export ARTIFACTORY_USERNAME="your-username"
export ARTIFACTORY_PASSWORD="your-access-token"
CREDS

# 2. Reload shell
source ~/.zshrc

# 3. Configure pip
./setup_pip.sh

# 4. Install
pip install findmytakeover

# 5. Verify
findmytakeover --help
```

## Usage

```bash
# Run with default config
findmytakeover

# Use custom config
findmytakeover -c myconfig.yaml

# Save results
findmytakeover -d results.json
```

## Cloud Setup

### AWS
```bash
aws configure
# Or use IAM roles on EC2
```

### Azure
```bash
az login
```

### GCP
```bash
gcloud auth application-default login
```

## Troubleshooting

```bash
# If package not found, re-run:
./setup_pip.sh

# Or install with full URL:
pip install --index-url https://artifactory.prod.auto1.team/artifactory/api/pypi/devops-artifacts/simple findmytakeover
```

## Publishing

```bash
export ARTIFACTORY_ACCESS_TOKEN="your-token"
make publish
```
