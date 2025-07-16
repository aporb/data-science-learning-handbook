# Comprehensive Research Report: Technology Platform Development Resources

## Executive Summary

This report provides comprehensive research on four critical technology platforms: Advana platform development, Qlik development and deployment, Databricks cluster provisioning and management, and the U.S. Navy's Jupiter environment. Each section includes official documentation, best practices, code samples, and recommended learning paths from authoritative sources.

---

## 1. Advana Platform Development

### Overview
Advana is the Department of Defense's enterprise data analytics platform, developed in partnership with Booz Allen Hamilton. Launched in 2019, it unifies data from over 3,000 business systems across the Army, Navy, and Air Force, supporting more than 7,000 users.

### Architecture & Technical Details
- **Visualization Layer**: Uses Qlik Sense with server-side extensions (SSEs) and mashups
- **Data Integration**: Combines 1,200+ systems into one central platform
- **Common Data Models**: Converts disparate data sources into standardized formats
- **Self-Service Analytics**: Provides natural language discovery and workspace-based analytics

### Official Resources & Documentation

**Primary Sources:**
- Booz Allen Case Study: [Advanced Enterprise Analytics at DoD](https://www.boozallen.com/d/insight/thought-leadership/advanced-enterprise-analytics-at-the-defense-department.html)
- Government Technology Insider Article: [How DoD Solved Data Interoperability Challenges](https://governmenttechnologyinsider.com/meet-advana-how-the-department-of-defense-solved-its-data-interoperability-challenges/)

**GitHub Repositories:**
- **Main Organization**: [dod-advana](https://github.com/dod-advana) (14 repositories)
- **Key Repositories**:
  - `gamechanger-web` - Web interface for evidence-based decision-making
  - `gamechanger` - Core GameChanger platform
  - `gamechanger-data` - Data processing components
  - `advana-module-platform-ui` - Platform UI module
  - `advana-module-api-auth` - Authentication module
  - `fiscam-automation` - Financial automation tools

**Training & Documentation:**
- DoD API Data Analytics: [Official Training Resources](https://www.acq.osd.mil/asda/dpc/api/data-analytics.html)
- Databricks Training through Advana platform
- Third-party training resources available through Advana Help Desk

### Development APIs & SDKs
- **Qlik Server-Side Extensions (SSEs)**: Enable backend systems to access functions across different systems
- **Qlik Mashups**: Combine content from multiple sources into unified interfaces
- **Platform Modules**: Available as npm packages through GitHub packages

### Best Practices & Security
- Government-owned data fabric approach
- Secure authentication through DoD networks
- Data classification and governance models
- Compliance with federal data standards

---

## 2. Qlik Development and Deployment

### Developer Resources

**Official Documentation Hub:**
- **Qlik Developer Portal**: [qlik.dev](https://qlik.dev/) - Primary resource for all Qlik development
- **API Documentation**: [REST APIs](https://qlik.dev/apis/rest/)
- **Legacy Documentation**: [Qlik Sense for Developers](https://help.qlik.com/en-US/sense-developer/)

### APIs & SDKs

**Core APIs:**
- **REST APIs**: Management, configuration, and integration
- **QIX Engine API**: Direct access to Qlik Associative Engine
- **Capability APIs**: Client-side development for extensions and mashups
- **Webhooks & Audits**: Event-driven automation

**Development Libraries:**
- **@qlik/api**: Typed library for REST and Analytics engine interaction
- **qlik-embed**: Primary embedding framework
- **nebula.js**: JavaScript libraries for custom visualizations
- **QVX SDK**: Custom connector development
- **.NET SDK**: Windows application integration

### Authentication Methods
- **OAuth 2.0**: Recommended for most use cases
- **JSON Web Tokens (JWT)**: Legacy embedding solutions
- **API Keys**: Simple access with user permissions
- **CSRF Tokens**: Required for browser-based requests

### Data Modeling & Development Best Practices

**Performance Optimization:**
- Minimize object count on sheets
- Use set analysis for conditional logic
- Implement proper caching strategies
- Optimize data load scripts with QVD files

**Learning Resources:**
- Motor.js Medium Blog: [Top Learning Resources for Qlik APIs](https://medium.com/motor-js/top-learning-resources-to-level-up-your-qlik-sense-api-skills-e3438fc45cb9)
- Qlik Branch Community: Industry trends and insights
- Data Flair: Comprehensive Qlik development tutorials

### Enterprise Deployment Architectures

**Small Deployment (< 100 users):**
- Single node with integrated repository and file share
- Basic authentication and user management

**Medium Deployment (100-500 users):**
- Multi-node setup with dedicated repository database
- Load balancing with proxy services
- Separate reload and consumer nodes

**Large Deployment (500-2000 users):**
- Central node with failover candidate
- Multiple consumer nodes for load distribution
- Dedicated developer nodes
- External PostgreSQL database and file share

**Extra-Large Deployment (2000+ users):**
- Seven consumer nodes with specialized clustering
- Dedicated proxy nodes for traffic management
- Advanced monitoring and performance optimization

### Performance Tuning Guidelines

**Infrastructure Requirements:**
- Network latency below 4ms between nodes
- SSD storage for optimal performance
- Dedicated SAN storage for enterprise deployments
- Regional VPC endpoints for cloud deployments

**Monitoring Tools:**
- Qlik Sense Enterprise Scalability Tools
- Log Analyzer applications
- Performance dashboards and metrics
- Automated health checks

---

## 3. Databricks Cluster Provisioning and Management

### Official Documentation & Resources

**Microsoft Learn (Azure):**
- [Getting Started Tutorials](https://learn.microsoft.com/en-us/azure/databricks/getting-started/)
- [Compute Configuration Reference](https://learn.microsoft.com/en-us/azure/databricks/compute/configure)
- [Cluster Management Guide](https://learn.microsoft.com/en-us/azure/databricks/compute/clusters-manage)

**Databricks Official Documentation:**
- [Compute Configuration Reference](https://docs.databricks.com/aws/en/compute/configure)
- [Cluster Management](https://docs.databricks.com/en/compute/clusters-manage.html)

### Step-by-Step Deployment Guides

**Azure Deployment:**
- [Automated Azure Setup Blog](https://www.databricks.com/blog/2020/09/16/automate-azure-databricks-platform-provisioning-and-configuration.html)
- ARM templates for workspace deployment
- VNET integration and security configuration
- Service principal authentication setup

**Best Practices Repositories:**
- **Azure Best Practices**: [Azure/AzureDatabricksBestPractices](https://github.com/Azure/AzureDatabricksBestPractices)
- **Notebook Best Practices**: [databricks/notebook-best-practices](https://github.com/databricks/notebook-best-practices)
- **Azure SQL Integration**: [Azure-Samples/azure-sql-db-databricks](https://github.com/Azure-Samples/azure-sql-db-databricks)

### Cluster Configuration & Autoscaling

**Autoscaling Features:**
- Optimized autoscaling for Premium workspaces
- Standard autoscaling for basic plans
- Enhanced autoscaling for streaming workloads
- GPU-enabled compute for deep learning

**Storage Configuration:**
- EBS GP3 volumes (AWS) with 50 TiB default limit
- Encrypted volumes for both on-demand and spot instances
- Customer-managed encryption keys support
- Local storage optimization options

### Development Best Practices

**Version Control Integration:**
- Git integration with GitHub, GitLab, Azure DevOps, Bitbucket
- Databricks Asset Bundles for unified deployment
- CI/CD workflows with GitHub Actions and Azure DevOps
- Branch management and collaborative development

**Code Samples & Tutorials:**
- [Azure Databricks Exercise](https://github.com/tsmatz/azure-databricks-exercise) - Hands-on tutorials
- COVID-19 data analysis examples
- ML pipeline development guides
- Delta Lake implementation patterns

### Security & Compliance

**Network Security:**
- Customer-managed VPC deployment
- Private endpoints and PrivateLink connectivity
- Network security groups and access controls
- IP access lists and firewall configuration

**Authentication & Authorization:**
- Azure Active Directory integration
- SCIM provisioning for user management
- Service principal authentication
- Workload identity federation for CI/CD

### Performance Optimization

**Cluster Optimization:**
- Instance type selection for workload requirements
- Spot instance usage for cost optimization
- Cluster policies for governance
- Performance monitoring and alerting

**Cost Management:**
- Automated cluster termination policies
- Reserved instance planning
- Usage monitoring and optimization
- Budgeting and cost allocation

---

## 4. U.S. Navy's Jupiter Environment

### Platform Overview
Jupiter is the Department of the Navy (DON) enterprise data environment, launched in April 2020. It serves as the central platform for making Navy data discoverable, accessible, understandable, and usable across the naval enterprise.

### Official Resources & Internal Documentation

**Navy CIO Sources:**
- CHIPS Articles: [Jupiter: Bringing Analytics to DON](https://www.doncio.navy.mil/chips/ArticleDetails.aspx?ID=13804)
- CHIPS Articles: [Streamlining Access to Jupiter](https://www.doncio.navy.mil/chips/ArticleDetails.aspx?ID=15370)
- CHIPS Articles: [Data Innovation Framework](https://www.doncio.navy.mil/chips/ArticleDetails.aspx?ID=14362)

**External Coverage:**
- MeriTalk: [Jupiter Platform Democratizing Data at Navy Reserve](https://www.meritalk.com/articles/jupiter-platform-democratizing-data-at-u-s-navy-reserve/)
- GovCIO Media: [Jupiter Sharpening Financial Management](http://govciomedia.com/how-navys-jupiter-enterprise-data-platform-is-sharpening-financial-management/)

### Authentication & Access Control

**User Access:**
- Common Access Card (CAC) authentication
- Personal Identity Verification (PIV) token support
- Free access for all DON personnel
- Baseline Access to DON Data and Analytics memo guidelines

**Security Features:**
- DoD network integration
- Secure data classification handling
- Role-based access controls
- Audit trails and compliance monitoring

### Platform Capabilities

**Data Analytics Features:**
- Decision support analytics and visualizations
- Context-rich data presentation
- Advanced data tools for analysts
- Cross-domain data integration

**Financial Management Focus:**
- General ledger consolidation
- Transaction volume monitoring ($1.7B daily)
- 15-minute increment processing capability
- Automated financial analytics

### Integration Points

**DoD Network Integration:**
- Seamless connectivity with DoD systems
- Data sharing with other federal agencies (HHS, FEMA)
- Cross-service collaboration (Army, Navy, Air Force)
- Enterprise-level data standardization

**Advanced Technologies:**
- Robotic Process Automation (RPA) integration
- Machine Learning capabilities (launched 6 months ago)
- Predictive modeling and analytics
- Real-time data processing

### Data Innovation Framework

**Framework Components:**
- Data democratization initiatives
- Operationalization of data science
- Rapid data ingestion and curation
- Cross-pollination of cloud systems and domain expertise

**Use Cases:**
- COVID-19 contact tracing and response
- PPE inventory tracking across federal agencies
- Financial audit automation
- Readiness assessment analytics

### Deployment Guidelines

**Access Requirements:**
- Valid CAC or PIV credentials
- DoD network connectivity
- Baseline security clearance
- Training completion (varies by role)

**Data Export Processes:**
- Controlled data extraction procedures
- Classification level management
- Audit trail maintenance
- Compliance with DoD data policies

---

## Recommended Learning Paths

### 1. Advana Platform Development
**Beginner Path:**
1. Complete DoD data analytics training modules
2. Familiarize with Qlik Sense basics
3. Explore GameChanger repositories on GitHub
4. Request Advana platform access through official channels

**Advanced Path:**
1. Deep dive into Qlik SSE and mashup development
2. Contribute to open-source Advana modules
3. Develop custom analytics solutions
4. Integrate with DoD data sources

### 2. Qlik Development
**Foundation (1-2 months):**
1. Qlik Developer Portal basics and tutorials
2. Capability APIs and embedding fundamentals
3. QIX Engine API exploration
4. Basic extension development

**Intermediate (3-6 months):**
1. Advanced mashup development
2. Custom connector creation with QVX SDK
3. Performance optimization techniques
4. Enterprise deployment planning

**Expert (6+ months):**
1. Complex multi-cloud deployments
2. Advanced security implementation
3. Custom visualization development
4. API automation and orchestration

### 3. Databricks Platform
**Getting Started (1 month):**
1. Azure Databricks tutorials on Microsoft Learn
2. Clone and explore best practices repositories
3. Complete hands-on exercises
4. Basic cluster configuration

**Intermediate (2-4 months):**
1. Implement CI/CD with Asset Bundles
2. Advanced cluster optimization
3. MLOps workflows and pipelines
4. Security and compliance configuration

**Advanced (4+ months):**
1. Multi-cloud deployment strategies
2. Custom connector development
3. Enterprise governance implementation
4. Performance tuning and cost optimization

### 4. Navy Jupiter Environment
**Access & Training:**
1. Obtain appropriate security clearance
2. Complete mandatory DoD training
3. Request Jupiter platform access
4. Attend Naval data analytics workshops

**Development Path:**
1. Understand Navy data standards and classifications
2. Learn DoD-specific analytics requirements
3. Develop familiarity with federal compliance standards
4. Contribute to Navy data innovation initiatives

---

## Conclusion

This comprehensive research provides the foundation for developing solutions across all four technology platforms. Each platform offers unique capabilities and requires specific expertise, but all share common themes of data democratization, advanced analytics, and enterprise-scale deployment considerations.

The combination of official documentation, community resources, code repositories, and best practice guides provides multiple learning paths for developers at all skill levels. Organizations should prioritize security, compliance, and performance optimization when implementing solutions on any of these platforms.

For the most current information, regularly check the official documentation sources and community forums, as these platforms continue to evolve rapidly with new features and capabilities.

---

## High-Quality Resources for ADVANA, Qlik, Databricks, and Navy Jupiter Development

Based on my comprehensive research, here are the authoritative resources, documentation, and guides for each platform:

### 1. ADVANA Platform Development

#### Official Documentation and Resources

**Primary Platform Resources:**
- **DoD Chief Digital and AI Office (CDAO)**: [ai.mil/Initiatives/Analytic-Tools/](https://www.ai.mil/Initiatives/Analytic-Tools/)[1]
  - ADVANA serves as DoD's enterprise data and analytics environment
  - Provides access to 400+ DoD business systems
  - Contains official platform documentation and user guides

**Technical Architecture:**
- **Cloud Infrastructure**: AWS-based with auto-scaling capabilities[2]
- **Data Processing**: Apache Spark, Databricks integration
- **Security**: CAC authentication, RBAC, multi-classification support (NIPR, SIPR, JWICS)
- **APIs**: Enterprise API Gateway development with Google Cloud Apigee[3]

**Key Features:**
- 400+ automated data pipelines
- 30+ AI/ML models in production
- Real-time streaming capabilities with millisecond latency
- Support for 100,000+ users across DoD[4]

#### Development Resources

**Data Integration:**
- **Real-time Data Replication**: Army BMA and OSD CDAO have implemented millisecond-level data replication from GFEBS and GCSS-Army into ADVANA[5]
- **ETL Automation**: Automated Extract, Transform, Load processes eliminate manual data processing
- **Data Quality**: Programmatic validation with automatic rejection of out-of-bounds results

**Security and Governance:**
- **Multi-Classification Environment**: NIPR, SIPR, JWICS support
- **DoD Compliance**: DISA IL4 authorization, continuous monitoring
- **Audit Requirements**: Daily audit records, annual third-party audits by Grant Thornton

#### Best Practices

**Development Approach:**
- Container-based deployments with hardening pipelines
- Infrastructure-as-code for automated provisioning
- DevSecOps integration for security compliance
- Microservices architecture for scalability

### 2. Qlik Development and Deployment

#### Official Documentation

**Core Developer Resources:**
- **Qlik Sense Developer Help**: [help.qlik.com/en-US/sense-developer/](https://help.qlik.com/en-US/sense-developer/May2025/)[6]
  - Comprehensive API reference and SDK documentation
  - Mashup development guides and examples
  - Extension development framework

**Key APIs and SDKs:**

**Backend API**[7]:
```javascript
this.backendApi.selectValues(dim, [value], true);
this.backendApi.selectRange([range], false);
this.backendApi.search("searchTerm");
```

**Qlik Engine JSON API**[8]:
- WebSocket-based protocol for real-time data communication
- Supports app creation, data loading, and system information retrieval
- Available at `https://[server]/dev-hub/engine-api-explorer`

**Repository Service API**[9]:
- REST web service for site configuration and management
- Automated task scheduling and license management
- JSON-formatted requests and responses

#### Development Examples and Templates

**Mashup Development**[10]:
- **Basic Templates**: Single page, multi-page, responsive designs
- **Code Examples**: HTML, JavaScript, CSS integration
- **API Integration**: Capability APIs for embedded analytics

**GitHub Integration**[11]:
- **Qlik GitHub Connector**: Direct repository analysis and data import
- **Automated Workflows**: Code deployment and version control
- **Data Sources**: Branches, commits, issues, pull requests

#### Deployment Architectures

**On-Premises Deployment**[12]:
- **Single-Node**: Basic deployment for up to 500 users
- **Multi-Node**: Scalable architecture for 1,000+ users
- **Central/Rim Node Configuration**: Load balancing and high availability

**Cloud Deployment**[13]:
- **Azure**: Native integration with Azure security features
- **AWS**: Streamlined deployment through AWS Marketplace[14]
- **Hybrid**: Mixed on-premises and cloud configurations

#### Training and Certification

**Official Training**[15]:
- **Qlik Sense Courses**: Free and instructor-led training modules
- **Certification Programs**: Analytics Development, Data Architect
- **Continuous Learning**: Self-paced videos, live webinars, expert coaching

**Community Resources**[16]:
- **YouTube Training**: 3+ hours of beginner to advanced tutorials
- **Coursera Projects**: Hands-on guided projects for practical skills
- **Community Forums**: Active developer community support

### 3. Databricks Cluster Provisioning and Management

#### Official Documentation

**Azure Databricks**[17]:
- **Workspace Creation**: Azure Portal, CLI, PowerShell, ARM templates
- **Cluster Configuration**: Node types, autoscaling, security modes
- **Performance Optimization**: Photon acceleration, runtime selection

**AWS Databricks**[18]:
- **Quick Start Guide**: Automated reference deployments
- **Partnership Solutions**: AWS Integration and Automation templates
- **Cost Management**: Spot instance integration, autoscaling policies

#### Cluster Configuration Best Practices

**Autoscaling Optimization**[19]:
```json
{
  "cluster_name": "production-cluster",
  "autoscale": {
    "min_workers": 2,
    "max_workers": 10
  },
  "auto_termination_minutes": 20,
  "node_type_id": "i3.xlarge"
}
```

**Security and Compliance**[20]:
- **Compliance Security Profile**: HIPAA, HITRUST, PCI-DSS support
- **Enhanced Security**: TLS 1.2+ encryption, automatic updates
- **Monitoring**: Security agents, audit logging, compliance reporting

#### Performance Tuning

**Cluster Sizing**[21]:
- **Access Modes**: Single user, shared, no isolation shared
- **Runtime Selection**: Latest for development, LTS for production
- **Instance Types**: Memory-optimized, compute-optimized, GPU-enabled

**Cost Optimization**[22]:
- **Reserved Instances**: Long-term commitment discounts
- **Spot Pricing**: Up to 90% cost reduction for fault-tolerant workloads
- **Instance Pools**: Reduced start times, improved resource utilization

#### Development Tools

**Databricks Connect**[23]:
- **IDE Integration**: VS Code, PyCharm, IntelliJ IDEA
- **Local Development**: Remote cluster execution from local environment
- **Language Support**: Python, Scala, R, SQL

**MLflow Integration**[24]:
- **Model Lifecycle**: Training, deployment, monitoring
- **Experiment Tracking**: Parameter logging, metric comparison
- **Model Registry**: Version control, stage management

### 4. U.S. Navy's Jupiter Environment

#### Official Platform Information

**Jupiter Overview**[25]:
- **Launch**: April 2020 as DON enterprise data environment
- **Purpose**: Make DON data discoverable, accessible, and actionable
- **Architecture**: Specialized community space within ADVANA

**Key Statistics**[26]:
- **Users**: 9,200+ across 65+ DON organizations
- **Applications**: 240+ Qlik applications
- **Data Connections**: 63 automated connections supporting 105 data sources
- **Networks**: NIPR, SIPR, JWICS support

#### Access and Authentication

**Access Requirements**[26]:
- **Authentication**: Common Access Card (CAC) required
- **Use Case Process**: Intake process for DON users
- **Classification Levels**: Business sensitive data, PII/PHI compliant
- **Access Points**: jupiter.data.mil (official portal)

**Tool Stack**[27]:
- **Analytics Tools**: Qlik Sense, Databricks, iQuery, Tableau
- **Data Management**: Collibra for data governance
- **Machine Learning**: Databricks notebooks for R, Python, SQL
- **Training Materials**: Comprehensive documentation and tutorials

#### Integration with DON Systems

**Data Governance**[25]:
- **Data Governance Board**: Chaired by DON Chief Data Officer
- **Information Domains**: 12 Naval Information Domains with dedicated stewards
- **Data Architecture**: Enterprise data hub with domain-specific integration

**Operational Benefits**[28]:
- **Financial Management**: Data processing acceleration from 30-45 days to 15 minutes
- **Transaction Volume**: $1.7 billion daily transaction processing
- **Analytics Integration**: HR, logistics, readiness, and acquisition data correlation

#### Development and Deployment

**Technical Environment**[29]:
- **Cloud Platform**: AWS-based infrastructure within ADVANA
- **Development Framework**: Agile methodology with JIRA and Confluence
- **Data Processing**: Real-time analytics and machine learning capabilities

**Use Case Examples**[30]:
- **Navy Reserve**: Democratized data science and operational analytics
- **Surface Analytics**: Task Force Hopper for AI/ML implementation
- **Readiness Assessment**: Comprehensive data catalog development

### Learning Paths and Recommendations

#### For Data Engineers
1. **Start with ADVANA**: Understanding DoD data architecture and security requirements
2. **Qlik Development**: Master APIs and mashup development for embedded analytics
3. **Databricks Clusters**: Learn autoscaling and performance optimization
4. **Jupiter Integration**: Understand Navy-specific use cases and workflows

#### For Analysts
1. **Qlik Sense Training**: Complete certification programs for business intelligence
2. **Jupiter Access**: Obtain CAC credentials and complete use case intake
3. **ADVANA Tools**: Learn iQuery, Tableau, and Databricks for comprehensive analysis
4. **Best Practices**: Follow DoD data governance and security protocols

#### For App Developers
1. **Qlik Mashups**: Master HTML, CSS, JavaScript integration with Qlik APIs
2. **Databricks Development**: Learn MLflow, Delta Lake, and model deployment
3. **ADVANA APIs**: Understand enterprise API gateway and data mesh architecture
4. **Security Implementation**: Implement CAC authentication and RBAC systems

#### For System Administrators
1. **Cluster Management**: Master multi-node Qlik deployments and Databricks optimization
2. **Security Compliance**: Implement DoD security standards and audit requirements
3. **Performance Monitoring**: Deploy comprehensive monitoring and alerting systems
4. **Cost Optimization**: Implement autoscaling and resource management strategies

This comprehensive resource guide provides authoritative documentation, practical examples, and strategic guidance for developing and deploying applications across all four platforms, with particular emphasis on the unique requirements and opportunities within the DoD and Navy environments.

[1] https://www.ai.mil/Initiatives/Analytic-Tools/
[2] https://www.boozallen.com/d/insight/thought-leadership/advanced-enterprise-analytics-at-the-defense-department.html
[3] https://cloud.google.com/blog/topics/public-sector/how-the-dod-unified-data-organization-wide-with-apigee
[4] https://breakingdefense.com/2024/07/advana-and-harvesting-the-value-of-defense/
[5] https://www.army.mil/article/270109/the_u_s_army_and_dod_chief_digital_and_artificial_intelligence_office_cdao_accelerate_the_speed_and_efficiency_of_data_with_two_data_replication_pipelines
[6] https://help.qlik.com/en-US/sense/May2025/Subsystems/Hub/Content/Sense_Hub/Introduction/developer-help.htm
[7] https://help.qlik.com/en-US/sense-developer/May2025/Subsystems/APIs/Content/Sense_ClientAPIs/backend-api-reference.htm
[8] https://help.qlik.com/en-US/sense-developer/May2025/Subsystems/EngineAPI/Content/Sense_EngineAPI/introducing-engine-API.htm
[9] https://help.qlik.com/en-US/sense-developer/May2025/Subsystems/RepositoryServiceAPI/Content/Sense_RepositoryServiceAPI/RepositoryServiceAPI-Introduction.htm
[10] https://data-flair.training/blogs/qlik-sense-mashup/
[11] https://help.qlik.com/en-US/connectors/Subsystems/Integrated_Web_Connectors_help/Content/Connectors_QWC_BuiltIn/Integrated%20connectors/GitHub-Connector-integrated.htm
[12] https://help.qlik.com/en-US/sense-admin/May2025/Subsystems/DeployAdministerQSE/Content/Sense_DeployAdminister/QSEoW/Deploy_QSEoW/Enterprise-deployment.htm
[13] https://help.qlik.com/en-US/sense-admin/May2025/Subsystems/DeployAdministerQSE/Content/Sense_DeployAdminister/QSEoW/Deploy_QSEoW/Azure-architecture.htm
[14] https://aws.amazon.com/about-aws/whats-new/2024/12/streamlined-deployment-experience-databricks-aws/
[15] https://www.mdpi.com/2078-2489/12/2/67/pdf?version=1612666019
[16] https://www.coursera.org/projects/qlik-sense-beginners-analyze-visualize-data
[17] https://learn.microsoft.com/en-us/azure/databricks/admin/workspace/
[18] https://aws-ia.github.io/cfn-ps-databricks-unified-data-analytics-platform/
[19] https://overcast.blog/13-ways-to-optimize-databricks-autoscaling-dfaa4a17637b
[20] https://learn.microsoft.com/en-us/azure/databricks/security/privacy/security-profile
[21] https://www.linkedin.com/pulse/cluster-configuration-databricks-best-practices-santos-saenz-ferrero-h1j0f
[22] https://cloudsecurityweb.com/articles/2025/04/04/10-ways-to-optimize-databricks-autoscaling-configurations/
[23] https://learn.microsoft.com/en-us/azure/databricks/dev-tools/databricks-connect/cluster-config
[24] https://ijsrcseit.com/index.php/home/article/view/CSEIT241061256
[25] https://www.doncio.navy.mil/mobile/ContentView.aspx?ID=13804&TypeID=21
[26] https://www.dau.edu/sites/default/files/webform/documents/26876/What%20is%20Jupiter.pdf
[27] https://www.mynavyhr.navy.mil/Career-Management/Community-Management/Operations-Analysis-Community/
[28] https://govciomedia.com/how-navys-jupiter-enterprise-data-platform-is-sharpening-financial-management/
[29] https://www.mdpi.com/2227-7080/11/6/165/pdf?version=1700494162
[30] https://meritalk.com/articles/jupiter-platform-democratizing-data-at-u-s-navy-reserve/
[31] https://www.mdpi.com/2571-9408/6/12/387
[32] https://dl.acm.org/doi/10.1145/3591106.3592277
[33] https://hdl.handle.net/11681/47908
[34] https://www.mdpi.com/2073-445X/14/5/1062
[35] https://diglib.eg.org/handle/10.2312/gch20221232
[36] https://ieeexplore.ieee.org/document/10181679/
[37] https://revista.profesionaldelainformacion.com/index.php/EPI/article/view/87132
[38] https://onlinelibrary.wiley.com/doi/10.1111/isj.12186
[39] https://www.mdpi.com/2076-3417/12/8/3728
[40] https://ieeexplore.ieee.org/document/10342152/
[41] https://comptroller.defense.gov/Portals/45/documents/fmr/current/01/01_10.pdf
[42] https://buildersummit.com/wp-content/uploads/2020/08/Advana-101-Briefing_JUL2021.pdf
[43] https://docs.aws.amazon.com/whitepapers/latest/aws-cloud-data-ingestion-patterns-practices/data-ingestion-patterns.html
[44] https://www.dla.mil/Portals/104/Documents/DLMS/Summit/Day1/10.%20DLA%20J6D%20Data%20Sharing%20(Carter).pdf
[45] https://news-cdn.orangeslices.ai/wp-content/uploads/2024/10/26120230/FA800324R0017-Attachment-1-PWS.1727964999051-dod-advana.pdf
[46] https://apps.dtic.mil/sti/trecms/pdf/AD1154570.pdf
[47] https://www.dau.edu/tools/advana
[48] https://github.com/dod-advana/advana-module-api-auth
[49] https://www.ndtahq.com/wp-content/uploads/2022/10/Journey-to-Advana-Erhardt-Midway-19-Session-5-Tue.pdf
[50] https://www.dfas.mil/Portals/98/Documents/Contractors-Vendors/Defense%20Agency%20Conference%202023/8%208%2023%201400%20World%20of%20Advana%20The%20Exploration%20of%20Analytics.pdf?ver=OiyaEWDq_kJGRShHsjazbg%3D%3D
[51] https://journalijsra.com/node/1306
[52] https://incose.onlinelibrary.wiley.com/doi/10.1002/j.2334-5837.2021.00827.x
[53] https://academic.oup.com/milmed/article/186/Supplement_1/49/6119491
[54] http://ieeexplore.ieee.org/document/6189431/
[55] http://www.dtic.mil/docs/citations/ADA496685
[56] https://www.sae.org/content/2024-01-3763
[57] https://arxiv.org/abs/2504.11744
[58] https://ieeexplore.ieee.org/document/8701025/
[59] https://www.semanticscholar.org/paper/fdfdf742f1dfb63192ade5ce01956475f0a806da
[60] https://arc.aiaa.org/doi/10.2514/6.1995-3546
[61] https://ppbe.servicedesigncollective.com/findings/2_poor_tech_and_security.html
[62] https://dodprocurementtoolbox.com/site-pages/advana-simplified-onboarding
[63] https://azuremarketplace.microsoft.com/en-us/marketplace/apps/kaviglobal1609169634872.advana?tab=overview
[64] https://www.acq.osd.mil/asda/dpc/api/data-analytics.html
[65] https://defensescoop.com/2025/03/17/make-advana-great-again/
[66] https://www.semanticscholar.org/paper/ea7b5d4b17ab5b43f7124b22eb4b06b783fab26c
[67] https://sol.sbc.org.br/index.php/eres/article/view/13733
[68] https://www.semanticscholar.org/paper/0a11aa3f6d89cc6dee3d69bbc1f5cd8b7de52756
[69] https://www.semanticscholar.org/paper/18a84b7bc12c9a76d86edd7adf9d98956a14dced
[70] https://www.semanticscholar.org/paper/0d5ed8955fa59365fb06b2c08036a6e08efff692
[71] https://www.semanticscholar.org/paper/cc97a59a0e9ecf7805ccee8ae4029bb93c53a3c5
[72] https://dl.acm.org/doi/10.1145/3639475.3640099
[73] https://dl.acm.org/doi/10.1145/2038476.2038517
[74] https://gmd.copernicus.org/articles/17/8593/2024/
[75] https://ijssr.ridwaninstitute.co.id/index.php/ijssr/article/view/1148
[76] https://help.qlik.com/en-US/sense-developer/May2025/Subsystems/RepositoryServiceAPI/Content/Sense_RepositoryServiceAPI/RepositoryServiceAPI-Access-OpenAPI-Spec.htm
[77] https://help.qlik.com/en-US/sense-admin/May2025/Subsystems/DeployAdministerQSE/Content/Sense_DeployAdminister/QSEoW/Administer_QSEoW/Managing_QSEoW/deployment-cloud-distribution.htm
[78] https://help.qlik.com/en-US/sense-developer/May2025/Content/Sense_Helpsites/APIs-and-SDKs.htm
[79] https://help.qlik.com/en-US/sense-admin/May2025/Subsystems/DeployAdministerQSE/Content/Sense_DeployAdminister/QSEoW/Administer_QSEoW/Managing_QSEoW/deployment-setup.htm
[80] https://community.qlik.com/t5/Official-Support-Articles/Qlik-Sense-Manuals-In-PDF-Format/ta-p/1714644
[81] https://www.mdpi.com/2079-9292/11/4/561/pdf?version=1645069528
[82] http://arxiv.org/pdf/2407.01620.pdf
[83] https://www.mdpi.com/1424-8220/21/17/5805/pdf
[84] https://arxiv.org/html/2410.08486v1
[85] http://arxiv.org/pdf/2407.12605.pdf
[86] https://arxiv.org/pdf/2310.01673.pdf
[87] https://arxiv.org/pdf/2502.20825.pdf
[88] https://arxiv.org/html/2504.07907
[89] https://arxiv.org/pdf/2212.03332.pdf
[90] https://arxiv.org/pdf/2105.01374.pdf
[91] https://ometis.co.uk/blog-news/qlik-sense-deployment-options
[92] https://help.qlik.com/en-US/sense-admin/May2025/Subsystems/DeployAdministerQSE/Content/Sense_DeployAdminister/QSEoW/Deploy_QSEoW/Installing-Qlik-Sense-multi-node.htm
[93] https://help.qlik.com/en-US/sense-admin/May2025/Subsystems/DeployAdministerQSE/Content/Sense_DeployAdminister/Common/qse-deployment-examples.htm
[94] https://www.youtube.com/watch?v=mGGArty3wKk
[95] https://help.qlik.com/en-US/sense-developer/May2025/Subsystems/Mashups/Content/Sense_Mashups/mashups-introduction.htm
[96] https://community.qlik.com/t5/Deployment-Management/Qlik-Sense-Cluster-installation/td-p/1176209
[97] https://www.datameer.com/blog/qlik-sense-mashups/
[98] https://help.qlik.com/en-US/sense-admin/May2025/Subsystems/DeployAdministerQSE/Content/Sense_DeployAdminister/QSEoW/Administer_QSEoW/Managing_QSEoW/service-cluster.htm
[99] https://www.semanticscholar.org/paper/4d3aeddaf6e14c6c3010fdbff16918905800be11
[100] https://arxiv.org/abs/2504.13747
[101] https://ieeexplore.ieee.org/document/10379373/
[102] https://journalwjarr.com/node/2008
[103] https://ieeexplore.ieee.org/document/10250700/
[104] https://www.semanticscholar.org/paper/1b733fddb370e38f89e17dddefb015c61fa2459d
[105] https://www.semanticscholar.org/paper/4d1c255fc35427b355c5f964bd5f063821749182
[106] https://ieeexplore.ieee.org/document/9079076/
[107] https://journalofbigdata.springeropen.com/articles/10.1186/s40537-023-00871-9
[108] https://dl.acm.org/doi/10.1145/3357223.3365870
[109] https://www.youtube.com/watch?v=RB1Cuv9-_Kc
[110] https://docs.databricks.com/gcp/en/admin/workspace/create-workspace
[111] https://www.mssqltips.com/sqlservertip/6604/azure-databricks-cluster-configuration/
[112] https://docs.databricks.com/aws/en/admin/workspace/
[113] https://overcast.blog/optimizing-databricks-autoscaler-51d8a236f7a5
[114] http://nti.khai.edu/ojs/index.php/reks/article/view/reks.2021.4.13
[115] https://ieeexplore.ieee.org/document/10838375/
[116] https://ieeexplore.ieee.org/document/10391973/
[117] https://www.ijeat.org/wp-content/uploads/papers/v9i5/E1023069520.pdf
[118] http://cctech.org.ua/13-vertikalnoe-menyu-en/284-abstract-21-3-7-arte
[119] https://ijsrset.com/index.php/home/article/view/IJSRSET2410614
[120] http://link.springer.com/10.1007/s10586-016-0599-0
[121] https://ieeexplore.ieee.org/document/10053466/
[122] https://ieeexplore.ieee.org/document/10175457/
[123] https://www.youtube.com/watch?v=jwooOK5h_vQ
[124] https://www.databricks.com/trust
[125] https://www.databricks.com/product/azure/security-and-compliance
[126] https://www.dvidshub.net/video/920290/jupiter
[127] https://www.databricks.com/blog/best-practices-and-guidance-cloud-engineers-deploy-databricks-aws-part-1
[128] https://www.semanticscholar.org/paper/c29a0bda5ef6dc094c61d2a5c93bba730f64431d
[129] https://linkinghub.elsevier.com/retrieve/pii/S147466701630578X
[130] https://www.semanticscholar.org/paper/54344bf700a6d1dafa1982cbb361ae03f718e2da
[131] https://arxiv.org/html/2411.12774v1
[132] http://arxiv.org/pdf/0801.1630.pdf
[133] https://www.mdpi.com/2073-4441/15/24/4236/pdf?version=1702103214
[134] https://arxiv.org/abs/2409.18405
[135] https://joss.theoj.org/papers/10.21105/joss.05728.pdf
[136] https://arxiv.org/html/2406.00935v1
[137] https://www.afcea.org/signal-media/west-22/navy-takes-helm-data-management
[138] https://cra.com/charles-river-analytics-wins-contract-from-us-navy-to-incorporate-human-ai-teaming-concepts-into-mission-planning/
[139] https://www.gdit.com/perspectives/latest/designing-building-and-implementing-an-authoritative-data-environment-ade/
[140] https://defensescoop.com/2022/08/03/ai-task-force-for-navy-surface-fleet-devising-comprehensive-data-catalog/
[141] https://www.dau.edu/tools/navy-data-environment-nde
[142] https://www.dau.edu/cop/DM/documents/what-jupiter
[143] https://www.dau.edu/tools/configuration-data-managers-database-open-architecture-cdmd-oa
[144] http://link.springer.com/10.1007/s11219-019-09483-0
[145] https://journals.sagepub.com/doi/10.1177/14614448221093943
[146] https://revistascientificas.cuc.edu.co/ingecuc/article/view/4065
[147] https://ieeexplore.ieee.org/document/9929480/
[148] https://ieeexplore.ieee.org/document/8816780/
[149] http://link.springer.com/10.1007/978-3-319-94229-2_37
[150] https://www.semanticscholar.org/paper/31861f4fc06e5b1fbe5551b5c5106a78ce57c85c
[151] https://www.semanticscholar.org/paper/69177e34c103786e0f426c253382faf6c9d26d8a
[152] https://ieeexplore.ieee.org/document/10811724/
[153] https://www.semanticscholar.org/paper/fc890cfdd40c3dcedf65159eefecd58dc05b94e9
[154] https://help.qlik.com/en-US/connectors/Subsystems/Web_Connectors_help/Content/Connectors_QWC/Data-Source-Connectors/Github-Connector.htm
[155] https://help.qlik.com/en-US/sense-developer/May2025/Subsystems/Dev-Hub/Content/Sense_Dev-Hub/Examples/dev-hub-code-examples.htm
[156] https://www.youtube.com/watch?v=ny8d2XlTWsQ
[157] https://help.qlik.com/en-US/sense-developer/May2025/Subsystems/Mashups/Content/Sense_Mashups/Examples/mashup-code-examples.htm
[158] https://community.qlik.com/t5/Application-Automation/Qlik-Sense-Automation-Push-Apps-to-GitHub-is-creating-repository/td-p/2470008
[159] https://clusterdesign.io/qlik-sense-demo-mashups/
[160] https://solutionsreview.com/business-intelligence/the-best-qlik-sense-training-and-courses/
[161] https://docs.gitoqlok.com/kick-start/connect-to-github/connect-qlik-sense-to-github
[162] http://arxiv.org/pdf/2408.02127.pdf
[163] http://arxiv.org/pdf/2404.10086.pdf
[164] https://www.mdpi.com/2227-9709/9/1/12/pdf
[165] https://arxiv.org/pdf/2003.12476.pdf
[166] http://arxiv.org/pdf/2405.13620.pdf
[167] https://www.frontiersin.org/articles/10.3389/fmed.2024.1365501/pdf?isPublishedV2=False
[168] https://arxiv.org/pdf/2210.10719.pdf
[169] https://arxiv.org/pdf/2302.11617.pdf
[170] https://docs.oracle.com/cd/E17287_04/otn/pdf/integration/E17315_01.pdf
[171] https://www.navysbir.com/n25_2/N252-096.htm
[172] https://www.acq.osd.mil/asda/dpc/ce/p2p/docs/training-presentations/2024/p2p%202024%20-%20procurement%20analytics%20data%20in%20advana%20part%20i.pdf
[173] https://www.acq.osd.mil/asda/dpc/api/docs/advana%203rd%20party%20training%20resources.pdf
[174] https://www.acq.osd.mil/asda/dpc/ce/p2p/docs/training-presentations/2022/Procurement-Business-Intelligence-System-Part-II.pdf
[175] https://www.acq.osd.mil/asda/dpc/ce/p2p/docs/training-presentations/2023/Procurement%20Analytics%20Data%20in%20Advana.pdf
[176] https://www.dau.edu/cop/DM/documents/introduction-data-and-analytics-advana
[177] https://www.advam.com/resources/developer-tools/
[178] https://dodprocurementtoolbox.com/uploads/Advana_Simplified_Onboarding_Process_Rotated_cc7e08447d.pdf
[179] https://figshare.com/articles/report/DoD_Architecture_Framework_and_Software_Architecture_Workshop_Report/6573281/1/files/12058847.pdf
[180] https://arxiv.org/pdf/2210.08818.pdf
[181] https://arxiv.org/pdf/2401.05358.pdf
[182] https://astesj.com/?download_id=3941&smd_process_download=1
[183] http://arxiv.org/pdf/2412.01328.pdf
[184] http://arxiv.org/pdf/2411.00511.pdf
[185] https://arxiv.org/ftp/arxiv/papers/1204/1204.0179.pdf
[186] https://figshare.com/articles/preprint/Scalable_and_Interoperable_Distributed_Architecture_for_IoT_in_Smart_Cities/24118458/1/files/42312618.pdf
[187] https://arxiv.org/pdf/1803.10664.pdf
[188] https://www.defense.gov/News/Releases/Release/Article/3910119/dod-chief-digital-and-ai-office-introduces-new-advana-at-industry-day-conferenc/
[189] https://arxiv.org/pdf/2409.12186.pdf
[190] https://arxiv.org/pdf/2201.04868v1.pdf
[191] https://arxiv.org/pdf/1809.03452.pdf
[192] https://arxiv.org/pdf/2207.02056.pdf
[193] http://arxiv.org/pdf/2403.14672.pdf
[194] https://arxiv.org/pdf/2308.06313.pdf
[195] https://arxiv.org/pdf/2310.05851.pdf
[196] https://dl.acm.org/doi/pdf/10.1145/3597503.3639187
[197] https://arxiv.org/pdf/2403.15667.pdf
[198] https://help.qlik.com/en-US/sense-developer/May2025/Subsystems/EngineJSONAPI/Content/introduction.htm
[199] https://qlik.dev/apis/
[200] https://qlik.dev/apis/rest/
[201] https://www.youtube.com/watch?v=6xTnqtZXzOA
[202] https://qlik.dev
[203] https://help.qlik.com/en-US/sense-developer/May2025/Content/Sense_Helpsites/Developer-help-windows.htm
[204] https://help.qlik.com/en-US/cloud-services/Subsystems/Hub/Content/Sense_Hub/Introduction/qcs-for-owners-and-admins.htm
[205] https://help.qlik.com/en-US/sense-developer/May2025/Content/Sense_Helpsites/Guides-developer.htm
[206] https://help.qlik.com/en-US/sense-developer/May2025/Subsystems/RepositoryServiceAPI/Content/Sense_RepositoryServiceAPI/RepositoryServiceAPI-Reference-Redirect.htm
[207] https://arxiv.org/pdf/2303.14713.pdf
[208] https://www.mdpi.com/1424-8220/23/4/2215
[209] https://www.mdpi.com/1424-8220/21/24/8212/pdf
[210] https://www.mdpi.com/1424-8220/24/24/7918
[211] http://arxiv.org/pdf/2407.20494.pdf
[212] http://arxiv.org/pdf/2407.17676.pdf
[213] https://arxiv.org/html/2504.03648v1
[214] http://arxiv.org/pdf/2503.07169.pdf
[215] https://www.mdpi.com/1424-8220/22/5/1755/pdf
[216] https://help.qlik.com/en-US/sense-developer/May2025/Subsystems/Mashups/Content/Sense_Mashups/mashups-build_cloud.htm
[217] https://help.qlik.com/en-US/sense-admin/February2024/pdf/Deploy%20Qlik%20Sense%20Enterprise%20on%20Windows.pdf
[218] https://community.qlik.com/t5/Management-Governance/Qliksense-Installation-and-Configuration-Best-Practice/td-p/1816794
[219] https://help.qlik.com/en-US/sense-developer/May2025/Subsystems/Mashups/Content/Sense_Mashups/mashups-start.htm
[220] https://community.qlik.com/t5/Visualization-and-Usability/Implement-QlikSense-on-premises/td-p/2008375
[221] https://help.qlik.com/en-US/catalog/February2023/Content/Resources/PDFs/QlikCatalog_February_2023_MultiNode_InstallGuide.pdf
[222] https://community.qlik.com/t5/Official-Support-Articles/Qlik-Sense-on-AWS-Deployment-Guide/ta-p/1716117
[223] https://community.qlik.com/t5/Official-Support-Articles/How-to-set-up-Monitoring-Apps-in-a-clustered-environment/ta-p/1717024
[224] https://arxiv.org/pdf/2412.02047.pdf
[225] https://arxiv.org/pdf/2011.07965.pdf
[226] https://arxiv.org/pdf/2405.00030.pdf
[227] https://arxiv.org/pdf/2211.16648.pdf
[228] https://arxiv.org/pdf/2502.21046.pdf
[229] https://arxiv.org/pdf/2409.16919.pdf
[230] https://arxiv.org/pdf/1906.06590.pdf
[231] https://arxiv.org/html/2410.05217
[232] https://www.mdpi.com/1099-4300/24/11/1606/pdf?version=1668594072
[233] https://arxiv.org/pdf/1908.01978.pdf
[234] https://www.chaosgenius.io/blog/databricks-workspaces/
[235] https://docs.databricks.com/aws/en/dlt/auto-scaling
[236] https://learn.microsoft.com/en-us/azure/databricks/compute/configure
[237] https://www.youtube.com/watch?v=q9HyiKLWfQY
[238] https://www.youtube.com/watch?v=OYHIaMhtPTg
[239] https://learn.microsoft.com/en-us/azure/databricks/compute/cluster-config-best-practices
[240] https://learn.microsoft.com/en-us/azure/databricks/getting-started/
[241] https://stackoverflow.com/questions/57145964/how-databricks-do-auto-scaling-for-a-cluster
[242] https://docs.databricks.com/aws/en/compute/configure
[243] https://www.databricks.com/resources/demos/videos/lakehouse-platform/setting-up-your-databricks-workspace-on-aws
[244] https://arxiv.org/pdf/2210.01073.pdf
[245] http://arxiv.org/pdf/1508.04973.pdf
[246] https://arxiv.org/pdf/2206.13852.pdf
[247] https://arxiv.org/abs/2102.08710
[248] http://arxiv.org/pdf/2408.11635.pdf
[249] https://www.ijfmr.com/papers/2023/6/11371.pdf
[250] https://pmc.ncbi.nlm.nih.gov/articles/PMC8276028/
[251] https://arxiv.org/pdf/2206.00429.pdf
[252] http://conference.scipy.org/proceedings/scipy2018/pdfs/adam_richie-halford.pdf
[253] https://www.databricks.com/trust/security-features
[254] https://docs.databricks.com/aws/en/security/
[255] https://www.databricks.com/trust/security-features/protect-your-data-with-enhanced-security-and-compliance
[256] https://news.usni.org/2021/05/19/department-of-navy-developing-data-tool-for-cos-to-understand-predict-behavior-of-marines-sailors
[257] https://community.databricks.com/t5/administration-architecture/databricks-in-aws-k8-cluster/td-p/103774
[258] https://docs.azure.cn/en-us/databricks/lakehouse-architecture/security-compliance-and-privacy/best-practices
[259] https://arxiv.org/pdf/2310.03196.pdf
[260] https://arxiv.org/abs/2305.00108
[261] https://arxiv.org/pdf/1812.01477.pdf
[262] https://www.mdpi.com/1424-8220/17/8/1802/pdf
[263] http://arxiv.org/pdf/2407.14602.pdf
[264] https://dl.acm.org/doi/pdf/10.1145/3626203.3670594
[265] https://arxiv.org/pdf/2404.02188.pdf
[266] https://www.mdpi.com/2226-4310/12/1/56
[267] https://arxiv.org/html/2402.18574v1
[268] https://arxiv.org/pdf/2402.01480.pdf
[269] https://www.doncio.navy.mil/(waig4wmmzy34e1jvuv1j0d45)/FileHandler.ashx?ID=19040
[270] https://www.mynavyhr.navy.mil/Support-Services/MyNavy-Career-Center/Pers-Pay-Support/TRIAD-Resources/EUCFR-Guide/
[271] https://www.logtool.com/Toolbox/navy-data-environment-nde
[272] https://s3.us-west-2.amazonaws.com/napa-2021/Shared-Services-Fourm_06_09_2022_Navy-FM-Modernization.pdf
[273] https://www.usni.org/magazines/proceedings/2019/march/fleet-initiative-improve-modernization-planning-ship
[274] https://www.navsea.navy.mil/Home/RMC/MARMC/External-Links/
[275] https://linkinghub.elsevier.com/retrieve/pii/S2352340919310674
[276] https://arxiv.org/pdf/2407.20900.pdf
[277] https://arxiv.org/html/2409.04643v1
[278] https://arxiv.org/html/2405.07197v1
[279] https://arxiv.org/html/2501.14663v1
[280] http://arxiv.org/pdf/2107.03761.pdf
[281] https://www.mdpi.com/2073-431X/13/2/33/pdf?version=1706174086
[282] http://arxiv.org/pdf/2403.08488.pdf
[283] https://help.qlik.com/en-US/sense-developer/May2025/Subsystems/Mashups/Content/Sense_Mashups/mashups-build-qsd-qseow.htm
[284] https://help.qlik.com/en-US/sense/May2025/Content/Sense_Helpsites/Tutorials.htm
[285] https://github.com/qlik-download
[286] https://www.youtube.com/watch?v=1gGvtm-JSpA
[287] https://www.qlik.com/us/services/training
[288] https://github.com/orgs/qlik-oss/repositories
[289] https://community.qlik.com/t5/Qlik-Sense-Documents/Qlik-Sense-Mashup-Development-Tutorial/ta-p/1576213
[290] https://osse.dc.gov/sites/default/files/dc/sites/osse/publication/attachments/Qlik%20Sense%20Training%20for%20Beginners.pdf
[291] https://github.com/orgs/qlik-download/repositories
[292] https://www.youtube.com/watch?v=YnVreEgMQQM