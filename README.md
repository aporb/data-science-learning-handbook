# Data Science Learning Handbook

A comprehensive, multi-platform data science learning resource designed for government and enterprise environments, covering everything from foundational concepts to advanced MLOps practices.

## 🎯 Project Overview

This handbook provides practical, hands-on guidance for data science across multiple platforms including Advana, Qlik, Databricks, and Navy Jupiter. It's designed to be:

- **Platform-agnostic** with specific guides for each environment
- **Security-focused** with DoD compliance standards
- **Practical** with real-world examples and case studies
- **Scalable** from individual learning to enterprise deployment

## 🏗️ Architecture

The project follows a modular architecture:

```
data-science-learning-handbook/
├── chapters/           # Core learning content
├── platform-guides/    # Platform-specific implementations
├── code-examples/      # Executable examples
├── api-docs/          # API documentation
├── docker/            # Container configurations
├── ci-cd/             # CI/CD pipelines
├── security-compliance/ # Security policies and scans
├── validation/        # Content validation framework
└── scripts/           # Automation scripts
```

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Git
- Python 3.11+ (optional, for local development)

### Setup

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd data-science-learning-handbook
   ```

2. **Run the setup script:**
   ```bash
   ./scripts/setup-dev-environment.sh
   ```

3. **Start the development environment:**
   ```bash
   docker-compose up -d
   ```

4. **Access services:**
   - Jupyter Lab: http://localhost:8888
   - MLflow: http://localhost:5000
   - Grafana: http://localhost:3000 (admin/admin)
   - Prometheus: http://localhost:9090
   - Documentation: http://localhost:8080

### Manual Setup

If you prefer manual setup:

```bash
# Create environment
conda env create -f environment.yml
conda activate ds-handbook

# Or with pip
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Start services
docker-compose up -d
```

## 📚 Learning Path

### Foundation Level
1. **Introduction to Data Science** - Core concepts and methodologies
2. **Python & R Foundations** - Language fundamentals for data science
3. **Data Acquisition** - Sourcing and collecting data
4. **Data Wrangling** - Cleaning and preprocessing

### Intermediate Level
5. **Exploratory Data Analysis** - Understanding your data
6. **Supervised Machine Learning** - Classification and regression
7. **Unsupervised Machine Learning** - Clustering and dimensionality reduction
8. **Deep Learning** - Neural networks and advanced techniques

### Advanced Level
9. **MLOps** - Production deployment and monitoring
10. **Data Visualization** - Effective communication
11. **Deployment** - Production systems
12. **Ethics & Governance** - Responsible AI
13. **Advanced Topics** - Cutting-edge techniques

## 🔧 Platform Integration

### Advana
- API integration patterns
- Security compliance
- Data governance
- Performance optimization

### Qlik
- Server-side extensions
- Data connectivity
- Visualization integration
- Enterprise deployment

### Databricks
- REST API usage
- Spark integration
- MLflow tracking
- Collaborative workflows

### Navy Jupiter
- Secure data handling
- Classification management
- Network isolation
- Audit trails

## 🔐 Security & Compliance

- **DoD 8570** compliance standards
- **NIST** cybersecurity framework
- **FedRAMP** authorization patterns
- **Zero Trust** architecture principles
- **Data classification** handling

## 📊 Monitoring & Observability

- **Prometheus** for metrics collection
- **Grafana** for visualization
- **MLflow** for experiment tracking
- **Security scanning** with automated reports

## 🧪 Development Workflow

### Using Taskmaster
This project uses Taskmaster for project management:

```bash
# View all tasks
task-master list --with-subtasks

# Get next task
task-master next

# Update task status
task-master set-status --id=1.1 --status=done

# Add new task
task-master add-task --prompt="Implement new feature"
```

### Development Commands
```bash
# Start development environment
docker-compose up -d

# Run tests
pytest tests/

# Security scan
./scripts/security/security-scanner.sh

# Generate documentation
./scripts/generate-docs.sh

# Validate content
./scripts/validate-content.sh
```

## 🐳 Docker Services

| Service | Port | Description |
|---------|------|-------------|
| Jupyter Lab | 8888 | Interactive development environment |
| MLflow | 5000 | Experiment tracking and model registry |
| PostgreSQL | 5432 | Database for MLflow backend |
| Redis | 6379 | Caching and message broker |
| Grafana | 3000 | Monitoring dashboards |
| Prometheus | 9090 | Metrics collection |
| Nginx | 80/443 | Reverse proxy and load balancer |
| Documentation | 8080 | Project documentation |

## 📁 Directory Structure

```
├── chapters/                 # Core learning content
│   ├── 01-introduction/
│   ├── 02-python-r-foundations/
│   ├── ...                 # 13 total chapters
├── platform-guides/         # Platform-specific guides
│   ├── advana/
│   ├── qlik/
│   ├── databricks/
│   └── navy-jupiter/
├── code-examples/          # Executable examples
├── api-docs/              # API documentation
├── docker/                # Container configurations
├── ci-cd/                 # CI/CD pipelines
├── security-compliance/   # Security policies
├── validation/            # Content validation
└── scripts/               # Automation scripts
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run validation checks
5. Submit a pull request

### Content Guidelines
- Follow the established chapter structure
- Include practical examples
- Ensure security compliance
- Add validation tests
- Update documentation

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: Use GitHub Issues for bug reports
- **Discussions**: Use GitHub Discussions for questions
- **Documentation**: Check the `/docs` directory
- **Security**: Report security issues privately

## 🔄 Continuous Integration

The project includes:
- **GitHub Actions** for automated testing
- **Security scanning** on every commit
- **Content validation** pipeline
- **Documentation generation**
- **Multi-platform testing**

## 📈 Project Status

- ✅ Project structure established
- ✅ Docker environment configured
- ✅ Security framework implemented
- ✅ Platform integration planned
- 🔄 Content development in progress
- ⏳ Validation framework setup
- ⏳ CI/CD pipeline configuration

---

**Built with ❤️ for the data science community**
