# Data Science Learning Handbook

A comprehensive, DoD-compliant educational platform for data science practitioners across multiple classification levels and computing environments.

## 🎯 Project Overview

This handbook provides a structured learning path for data science professionals working in secure government environments. It covers foundational concepts through advanced topics, with practical examples and platform-specific guidance for Advana, Qlik, Databricks, and Navy Jupiter systems.

### Key Features
- **Multi-Platform Support**: Tailored guidance for Advana, Qlik, Databricks, and Navy Jupiter
- **Security-First Design**: DoD-compliant with multi-classification support
- **Interactive Learning**: Hands-on code examples with secure sandbox environments
- **Comprehensive Coverage**: 13 chapters from basics to advanced topics
- **MLOps Integration**: Complete model lifecycle management
- **Real-World Examples**: Practical use cases from government data science

## 📚 Chapter Structure

| Chapter | Title | Focus Area | Classification Level |
|---------|-------|------------|---------------------|
| 01 | Introduction | Data Science Fundamentals | Unclassified |
| 02 | Python & R Foundations | Programming Basics | Unclassified |
| 03 | Data Acquisition | Data Collection Methods | Secret+ |
| 04 | Data Wrangling | Data Cleaning & Prep | Secret+ |
| 05 | Exploratory Analysis | EDA & Visualization | Secret+ |
| 06 | Supervised ML | Classification & Regression | Secret+ |
| 07 | Unsupervised ML | Clustering & Dimensionality | Secret+ |
| 08 | Deep Learning | Neural Networks & DL | Top Secret+ |
| 09 | MLOps | Model Lifecycle Management | Secret+ |
| 10 | Visualization | Advanced Visualization | Secret+ |
| 11 | Deployment | Model Deployment Strategies | Top Secret+ |
| 12 | Ethics & Governance | Responsible AI | Secret+ |
| 13 | Advanced Topics | Cutting-Edge Techniques | Top Secret+ |

## 🏗️ Architecture

### Platform Integration
- **Advana**: REST API integration with CAC/PIV authentication
- **Qlik**: Server-side extensions and visualization integration
- **Databricks**: Unified analytics platform with MLflow
- **Navy Jupiter**: Secure data processing and analysis

### Security Architecture
- Multi-classification data handling
- CAC/PIV smart card authentication
- OAuth 2.0 with RBAC
- End-to-end encryption
- Audit logging and compliance monitoring

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Docker & Docker Compose
- Git
- Platform-specific credentials (CAC/PIV card)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd data-science-learning-handbook

# Set up development environment
./scripts/setup-dev-environment.sh

# Build Docker containers
docker-compose up --build

# Access the platform
# - Local: http://localhost:8080
# - Advana: Via DoD gateway
# - Databricks: Through secure connection
```

## 📖 Usage

### Learning Path
1. Start with Chapters 01-02 for fundamentals
2. Progress through Chapters 03-07 for core data science
3. Explore Chapters 08-09 for advanced topics
4. Apply knowledge with Chapters 10-13

### Interactive Examples
Each chapter includes:
- Jupyter notebooks with executable code
- Real datasets (synthetic for lower classifications)
- Platform-specific implementations
- Security considerations and best practices

## 🔧 Development

### Project Structure
```
data-science-learning-handbook/
├── chapters/           # Educational content
├── code-examples/      # Interactive code samples
├── platform-guides/    # Platform-specific documentation
├── api-docs/          # API documentation
├── docker/            # Container configurations
├── ci-cd/             # CI/CD pipelines
├── security-compliance/ # Security policies and scans
├── validation/        # Content validation and testing
└── templates/         # Reusable templates
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Follow the contribution guidelines
4. Submit a pull request with security review

### Development Setup
```bash
# Install dependencies
pip install -r requirements.txt
conda env create -f environment.yml

# Run tests
pytest tests/
npm test

# Security scan
./scripts/security-scan.sh
```

## 🔐 Security & Compliance

### Data Classification
- **Unclassified**: Public datasets and examples
- **Secret**: Government-specific use cases
- **Top Secret**: Advanced techniques and sensitive data

### Compliance Standards
- DoD 8570/8140 compliance
- NIST SP 800-53 controls
- FedRAMP authorization
- Section 508 accessibility

## 📊 Monitoring & Analytics

### Key Metrics
- Learning completion rates
- Platform usage analytics
- Security incident tracking
- Performance benchmarks

### Dashboard Access
- Development: http://localhost:3000/dashboard
- Production: Via secure gateway

## 🤝 Support

### Documentation
- [API Documentation](api-docs/)
- [Platform Guides](platform-guides/)
- [Architecture Docs](docs/architecture/)

### Getting Help
- Create an issue for bugs
- Security concerns: Contact security team
- Platform-specific: Check respective guides

## 📄 License

This project is licensed under the DoD Open Source License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- DoD Data Science Community
- Platform teams (Advana, Qlik, Databricks, Navy Jupiter)
- Security and compliance teams
- Educational content contributors
