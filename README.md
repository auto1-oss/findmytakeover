# findmytakeover

Detects dangling DNS records and potential subdomain takeovers across AWS, Azure, and GCP.

findmytakeover scans DNS zones and cloud infrastructure to find DNS records pointing to non-existent resources, identifying potential subdomain takeover vulnerabilities.

## Installation

### 1. Setup Authentication

Add to `~/.zshrc` or `~/.bashrc`:

```bash
export ARTIFACTORY_USERNAME="your-username"
export ARTIFACTORY_PASSWORD="your-access-token"
```

Then reload:
```bash
source ~/.zshrc  # or source ~/.bashrc
```

### 2. Configure pip

```bash
./setup_pip.sh
```

### 3. Install

```bash
pip install findmytakeover
```

## Cloud Provider Permissions

Required read-only permissions:

- **AWS**: `ViewOnlyAccess` and `SecurityAudit` roles
- **Azure**: `Reader` role  
- **GCP**: `Viewer` role

## Usage

```bash
# Basic scan with default config
findmytakeover

# Use custom config file
findmytakeover -c myconfig.yaml

# Save output to file
findmytakeover -d output.json

# Help
findmytakeover --help
```

## Configuration

Create `findmytakeover.config` file:

```yaml
exclude:
  ipaddress:
    - 100.1.0.0/16
  
cloud_providers:
  aws:
    accounts:
      - name: production
        role_arn: arn:aws:iam::123456789:role/ReadOnly
      - name: staging
        role_arn: arn:aws:iam::987654321:role/ReadOnly
  
  azure:
    subscriptions:
      - subscription_id: xxxx-xxxx-xxxx
        tenant_id: yyyy-yyyy-yyyy
  
  gcp:
    projects:
      - project_id: my-project-123
```

See `findmytakeover.config.example` for full configuration options.

## Output

Results are saved as JSON with detected vulnerabilities:

```json
{
  "vulnerable_records": [
    {
      "domain": "app.example.com",
      "record_type": "CNAME",
      "target": "old-app.cloudprovider.com",
      "vulnerability": "Dangling CNAME - target does not exist"
    }
  ]
}
```

## Supported Services

### AWS
- S3 buckets
- CloudFront distributions
- Elastic Beanstalk
- ELB/ALB
- API Gateway
- Route53

### Azure
- Storage accounts
- CDN endpoints
- App Services
- Traffic Manager
- API Management
- Container instances

### GCP
- Cloud Storage
- Cloud Functions
- Compute Engine
- Cloud Run
- App Engine

## Publishing

```bash
export ARTIFACTORY_ACCESS_TOKEN="your-token"
./publish.sh
```

## Development

```bash
# Install in development mode
make install

# Build package
make build

# Run tests
make test

# Clean build artifacts
make clean
```

## Why This Matters

Dangling DNS records allow attackers to:
- Host malicious content under your domain
- Launch phishing campaigns
- Damage your organization's reputation
- Intercept traffic meant for your services

## Requirements

- Python 3.8+
- Cloud provider credentials configured
- Access to DNS zones in your cloud accounts

## Troubleshooting

**Package not found:**
```bash
# Re-run setup
./setup_pip.sh

# Or install directly
pip install --index-url https://artifactory.prod.auto1.team/artifactory/api/pypi/devops-artifacts/simple findmytakeover
```

**No cloud credentials:**
```bash
# AWS
aws configure

# Azure
az login

# GCP
gcloud auth application-default login
```

## License

GPL-3.0

## Credits

Original tool by [anirudhbiyani](https://github.com/anirudhbiyani/findmytakeover)
