# Quick Start Guide

## Prerequisites

- Docker Desktop (Windows/Mac) or Docker Engine (Linux)
- 16GB+ RAM
- 100GB+ free disk space
- Git

## Installation in 5 Steps

### Step 1: Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/soc-in-a-box.git
cd soc-in-a-box
```

### Step 2: System Configuration

```bash
# Linux/WSL only
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

# Create Docker network
docker network create soc-network
```

### Step 3: Deploy Wazuh

```bash
# Clone Wazuh Docker
git clone https://github.com/wazuh/wazuh-docker.git -b v4.7.2
cd wazuh-docker/single-node

# Generate certificates
docker compose -f generate-indexer-certs.yml run --rm generator

# Start Wazuh
docker compose up -d
```

Wait 3-5 minutes, then access: **https://localhost:443**
- Username: `admin`
- Password: `SecretPassword`

### Step 4: Deploy Other Services

```bash
cd ../../docker

# Start TheHive + Cortex
docker compose -f docker-compose.thehive.yml up -d

# Start Shuffle
docker compose -f docker-compose.shuffle.yml up -d

# Start Caldera
docker compose -f docker-compose.caldera.yml up -d
```

### Step 5: Verify Installation

```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

You should see all containers running!

## Access URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| Wazuh | https://localhost:443 | admin / SecretPassword |
| TheHive | http://localhost:9000 | admin@thehive.local / secret |
| Cortex | http://localhost:9001 | admin / admin |
| Shuffle | http://localhost:3001 | admin / shuffle123 |
| Caldera | http://localhost:8888 | red / admin |

## Next Steps

1. **Install Agents**: See [Installation Guide](docs/installation/README.md)
2. **Deploy Detection Rules**: See [Detection Rules](detection-rules/README.md)
3. **Test Attacks**: See [Attack Scenarios](docs/attack-scenarios/README.md)
4. **Configure Playbooks**: See [Playbooks](playbooks/README.md)

## Troubleshooting

**Containers not starting?**
```bash
docker compose logs -f
sudo sysctl -w vm.max_map_count=262144
```

**Can't access dashboards?**
```bash
# Check if containers are running
docker ps

# Check specific service
docker logs <container_name>
```

## Support

- 📖 [Full Documentation](docs/)
- 🐛 [Report Issues](https://github.com/YOUR_USERNAME/soc-in-a-box/issues)
- 💬 [Discussions](https://github.com/YOUR_USERNAME/soc-in-a-box/discussions)
