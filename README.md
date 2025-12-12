# BASTION

<img width="414" height="515" alt="BASTION Logo" src="https://github.com/user-attachments/assets/189e9e9b-36b1-4488-9651-9a3ec468a8ab" />

**Bridging Attack Simulations To Integrated Observability Network**

A Caldera 5.3 plugin that integrates Breach and Attack Simulation (BAS) with Wazuh 4.14 SIEM for automated detection validation and security posture assessment.

---

## Repository Structure

This repository contains the **full development environment** for BASTION, including:

- Caldera server with all plugins
- Wazuh SIEM stack (Manager, Indexer, Dashboard)
- Docker Compose orchestration
- Development tools and configurations

### Looking for the Plugin Only?

If you want to install BASTION as a standalone Caldera plugin:

**[caldera-bastion](https://github.com/seosamuel02/caldera-bastion)** - Standalone plugin repository for Caldera integration

---

## Features

- **Automated Agent Correlation**: Automatically maps Caldera agents to Wazuh agents
- **Real-time Detection Validation**: Correlates attack simulations with SIEM detections
- **MITRE ATT&CK Coverage**: Visual heat map of technique coverage and detection gaps
- **Security Posture Scoring**: Quantified security assessment based on detection rates
- **Cyber Command Center Dashboard**: Professional SOC-style interface

## Architecture

```
+-------------------+     +------------------+     +------------------+
|                   |     |                  |     |                  |
|  Caldera Server   |<--->|  BASTION Plugin  |<--->|   Wazuh SIEM     |
|  (BAS Platform)   |     |  (Integration)   |     |  (Detection)     |
|                   |     |                  |     |                  |
+-------------------+     +------------------+     +------------------+
        |                        |                        |
        v                        v                        v
   Attack Agents          Correlation Engine        Security Alerts
```

## Quick Start

### Prerequisites

- Docker & Docker Compose
- 16GB+ RAM recommended
- Windows 10/11 or Linux

### Setup

```bash
# Clone the repository
git clone https://github.com/seosamuel02/BASTION.git
cd BASTION/bastion

# Start the environment
docker-compose up -d

# Wait for services to initialize (2-3 minutes)
docker-compose logs -f caldera
```

### Access

| Service | URL | Credentials |
|---------|-----|-------------|
| Caldera Dashboard | http://localhost:8888 | admin / admin |
| BASTION Plugin | http://localhost:8888/plugins/bastion | (same as Caldera) |
| Wazuh Kibana | http://localhost:5601 | elastic / Kimdong2024 |

## Documentation

- [BASTION_PRD.md](./BASTION_PRD.md) - Product Requirements Document
- [CLAUDE.md](./CLAUDE.md) - Development Guide (Korean)
- [Plugin README](./bastion/caldera/plugins/bastion/README.md) - Plugin Documentation

## Plugin Installation (Standalone)

For installing BASTION on an existing Caldera instance:

```bash
# Clone the plugin repository
cd /path/to/caldera/plugins
git clone https://github.com/seosamuel02/caldera-bastion.git bastion

# Install dependencies
pip install -r bastion/requirements.txt

# Add to local.yml
echo "  - bastion" >> /path/to/caldera/conf/local.yml

# Restart Caldera
```

## Contributing

Contributions are welcome! Please see the [caldera-bastion](https://github.com/seosamuel02/caldera-bastion) repository for plugin-specific contributions.

## License

Apache License 2.0

---

*2025 seosamuel*
