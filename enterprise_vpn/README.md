# Enterprise WireGuard VPN

A secure, enterprise-grade VPN solution built on WireGuard with advanced security features including continuous authentication, threat monitoring, and granular access control.

## Features

- **Zero Trust Security Model**
  - BeyondCorp-style continuous authentication
  - Device trust verification
  - Context-aware access control
  - Real-time risk assessment

- **Advanced Monitoring**
  - Real-time threat detection
  - Behavior analysis
  - Policy compliance monitoring
  - Comprehensive audit logging

- **Granular Access Control**
  - Resource-based policies
  - Time-based restrictions
  - Location-based access
  - IP and port filtering

## Prerequisites

- Python 3.8 or higher
- WireGuard installed on both server and client machines
- Administrative privileges for network configuration
- (Optional) Okta account for enterprise authentication

## Installation

1. Install WireGuard:
   ```bash
   # Ubuntu/Debian
   sudo apt install wireguard

   # macOS
   brew install wireguard-tools

   # Windows
   # Download from https://www.wireguard.com/install/
   ```

2. Install the Enterprise VPN package:
   ```bash
   pip install -e .
   ```

## Server Setup

1. Initialize the VPN server:
   ```bash
   enterprise-vpn server init \
     --endpoint your-server.com \
     --subnet 10.0.0.0/24 \
     --port 51820
   ```

2. Configure authentication (for Okta):
   ```bash
   enterprise-vpn server config auth \
     --provider okta \
     --domain your-domain.okta.com \
     --api-token your-api-token
   ```

3. Create access policies:
   ```bash
   enterprise-vpn server policy add \
     --name "Development Access" \
     --resources "dev-servers" \
     --allowed-ips 10.0.0.0/24 \
     --allowed-ports 22,80,443 \
     --access-level READ
   ```

4. Start the server:
   ```bash
   enterprise-vpn server start
   ```

## Client Usage

1. Connect to VPN:
   ```bash
   enterprise-vpn connect \
     --username your.email@company.com \
     --server your-server.com \
     --subnet 10.0.0.0/24
   ```

2. Check connection status:
   ```bash
   enterprise-vpn status
   ```

3. View active policies:
   ```bash
   enterprise-vpn policy list
   ```

4. Disconnect:
   ```bash
   enterprise-vpn disconnect
   ```

## Security Configuration

### BeyondCorp Settings

Configure zero-trust security settings in `config/beyondcorp.yaml`:
```yaml
device_trust:
  minimum_score: 0.7
  required_security_features:
    - firewall
    - antivirus
    - disk_encryption

context_validation:
  allowed_locations:
    - office
    - verified_home
  allowed_time_windows:
    - weekday_business_hours
    - on_call_hours

risk_assessment:
  max_risk_level: MEDIUM
  continuous_validation_interval: 300  # seconds
```

### Access Policies

Define granular access policies in `config/policies.yaml`:
```yaml
policies:
  development:
    resources:
      - dev-servers
      - staging-env
    allowed_ips: ["10.0.0.0/24"]
    allowed_ports: [22, 80, 443]
    access_level: READ
    time_restrictions:
      weekdays: "09:00-17:00"
    location_restrictions:
      - office
      - verified_home

  production:
    resources:
      - prod-servers
    allowed_ips: ["10.0.0.0/24"]
    allowed_ports: [22]
    access_level: ADMIN
    time_restrictions:
      weekdays: "09:00-17:00"
    location_restrictions:
      - office
```

## Monitoring and Logs

1. View real-time metrics:
   ```bash
   enterprise-vpn monitor metrics
   ```

2. Check security events:
   ```bash
   enterprise-vpn monitor events --level WARNING
   ```

3. Access audit logs:
   ```bash
   enterprise-vpn logs audit --start-time "2023-12-01" --end-time "2023-12-02"
   ```

## Development and Testing

1. Set up development environment:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -e ".[dev]"
   ```

2. Run tests:
   ```bash
   pytest tests/
   ```

3. Run security checks:
   ```bash
   enterprise-vpn security check
   ```

## Troubleshooting

1. Check VPN status:
   ```bash
   enterprise-vpn diagnostics status
   ```

2. Test connectivity:
   ```bash
   enterprise-vpn diagnostics ping
   ```

3. Verify security:
   ```bash
   enterprise-vpn diagnostics security
   ```

## Security Considerations

1. **Authentication**:
   - Use strong passwords
   - Enable MFA when possible
   - Regularly rotate API tokens

2. **Network Security**:
   - Keep WireGuard updated
   - Use secure DNS
   - Monitor for unusual traffic

3. **Access Control**:
   - Follow principle of least privilege
   - Regularly audit access policies
   - Monitor policy violations

## License

MIT License - see LICENSE.txt for details 