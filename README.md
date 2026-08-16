# VULNIQ

## Machine Learning Based Vulnerability Profiling & Threat Intelligence Workflow

VULNIQ is a machine learning project that applies **unsupervised clustering** to cybersecurity vulnerability data to identify meaningful vulnerability profiles beyond traditional severity-based classification.

The project combines vulnerability characteristics such as **CVSS metrics, EPSS exploit probability, CISA Known Exploited Vulnerability (KEV) status, attack characteristics, and vulnerability age**.

The resulting clusters are then enriched with threat intelligence information such as **CWE, vendor, and product data** to make the clusters more interpretable and useful for vulnerability analysis.

---

## Project Objective

Traditional vulnerability management often relies heavily on CVSS severity scores.

However, vulnerabilities with similar severity scores can have very different:

- Exploitability characteristics
- Attack vectors
- Impact levels
- Exploitation likelihood
- Vulnerability age
- Known exploitation status

The objective of VULNIQ is to use **unsupervised machine learning** to discover vulnerability groups based on multiple technical and threat-related characteristics.

The resulting groups can support activities such as:

- Vulnerability profiling
- Remediation campaign planning
- Threat intelligence analysis
- Identification of high-risk vulnerability groups
- Prioritization beyond severity alone

---

## Dataset Source

The datasets used in this project were obtained from the Kaggle **CVE, CISA KEV & EPSS Datasets** collection.

[CVE, CISA KEV & EPSS Datasets on Kaggle](https://www.kaggle.com/datasets/francescomanzoni/vulnerability-management-datasets)

### Primary Vulnerability Dataset

```text
cve_cisa_epss_enriched_dataset.csv
```

The primary dataset contains **346,232 CVE records**.

Key attributes include:

- CVE ID
- CVSS Base Score
- Exploitability Score
- Impact Score
- EPSS Score
- EPSS Percentile
- CISA KEV status
- Attack Vector
- Attack Complexity
- Privileges Required
- User Interaction
- Scope
- Confidentiality Impact
- Integrity Impact
- Availability Impact
- Published Date

### Threat Intelligence Dataset

```text
cve_corpus.csv
```

The second dataset is used to enrich the resulting vulnerability clusters with additional threat intelligence information.

The following information is extracted:

- CWE
- CPE
- Vendor
- Product

The `cve_corpus.csv` file is approximately **296 MB** and is therefore not included directly in this GitHub repository.

After downloading the datasets from Kaggle, place them in:

```text
VULNIQ/data/raw/
```

Expected structure:

```text
data/raw/
├── cve_cisa_epss_enriched_dataset.csv
└── cve_corpus.csv
```

---

## Machine Learning Workflow

The project follows the pipeline below:

```text
Raw Vulnerability Data
        |
        v
Data Preprocessing
        |
        v
Feature Engineering
        |
        v
Feature Selection
        |
        v
One-Hot Encoding & Scaling
        |
        v
Clustering Experiments
   /        |         \
K-Means  Agglomerative  DBSCAN
   |
   v
Final K-Means Model (K=4)
   |
   v
Threat Intelligence Enrichment
   |
   v
Cluster Profiling
   |
   v
Visualization & Results
```

---

## 1. Data Preprocessing

The preprocessing stage performs:

- Dataset inspection
- Data type analysis
- Missing-value analysis
- Duplicate CVE analysis
- CVSS attribute validation
- Numerical distribution analysis
- Potential outlier analysis

Missing CVSS v3-specific attributes are represented using:

```text
NOT_DEFINED
```

Missing EPSS values are handled using **median imputation**.

---

## 2. Feature Engineering

A new feature called:

```text
vulnerability_age_days
```

is created using the vulnerability publication date.

A fixed reference date of:

```text
2026-08-01
```

is used to make the analysis reproducible.

The feature represents how long a vulnerability has existed at the time of analysis.

---

## 3. Feature Selection

Variance and correlation analysis were used to understand the numerical features before selecting the final clustering features.

The following **15 features** were selected:

```text
base_score
exploitability_score
impact_score
epss_score
epss_perc
cisa_kev
attack_vector
attack_complexity
privileges_required
user_interaction
scope
confidentiality_impact
integrity_impact
availability_impact
vulnerability_age_days
```

---

## 4. Encoding and Scaling

Categorical vulnerability attributes are transformed using **One-Hot Encoding**.

The numerical features are standardized using **StandardScaler**.

The numerical features standardized are:

```text
base_score
exploitability_score
impact_score
epss_score
epss_perc
vulnerability_age_days
```

After encoding and scaling, the clustering dataset contains:

```text
346,232 rows
39 features
```

---

## 5. Clustering Algorithms

Three unsupervised clustering algorithms were evaluated:

1. K-Means
2. Agglomerative Clustering
3. DBSCAN

This allowed different clustering approaches to be compared before selecting the final model.

---

## K-Means Clustering

K-Means clustering was evaluated with different values of K.

The final model uses:

```text
K = 4
```

The four-cluster solution was selected to provide distinct and interpretable vulnerability profiles for subsequent threat intelligence analysis.

### Final Cluster Distribution

| Cluster | Number of CVEs | Percentage |
|---|---:|---:|
| Cluster 0 | 6,100 | 1.76% |
| Cluster 1 | 107,124 | 30.94% |
| Cluster 2 | 69,839 | 20.17% |
| Cluster 3 | 163,169 | 47.13% |

---

## Agglomerative Clustering

Agglomerative clustering was evaluated using a representative **20,000-row sample**.

The sample was stratified using CISA KEV status to preserve the proportion of known exploited vulnerabilities.

A sample was used because hierarchical clustering is significantly more computationally expensive on the complete dataset.

### Silhouette Scores

| K | Silhouette Score |
|---|---:|
| 2 | 0.3476 |
| 3 | 0.2275 |
| 4 | 0.2441 |
| 5 | 0.2035 |
| 6 | 0.2022 |

The strongest silhouette score for Agglomerative Clustering was obtained with:

```text
K = 2
Silhouette Score = 0.3476
```

---

## DBSCAN Clustering

DBSCAN was also evaluated using a representative **20,000-row sample**.

A K-distance plot was used to investigate appropriate `eps` values.

Different values were tested before selecting:

```text
eps = 2.25
min_samples = 5
```

The final DBSCAN model produced:

```text
3 clusters
27 noise points
0.14% noise
```

The DBSCAN distribution was highly imbalanced, with the majority of vulnerabilities concentrated in one cluster.

---

## Final Model Selection

**K-Means with K=4** was selected as the final clustering model.

Although the alternative algorithms provided useful comparisons, K-Means produced four distinct vulnerability groups that could be profiled and enriched with threat intelligence.

This made the K-Means solution suitable for the final vulnerability profiling workflow.

---

## Numerical Cluster Characteristics

The standardized mean profiles of the final K-Means clusters are:

| Cluster | Base Score | Exploitability | Impact | EPSS | EPSS Percentile | Vulnerability Age |
|---|---:|---:|---:|---:|---:|---:|
| 0 | 0.83 | 0.42 | 0.68 | 6.57 | 1.69 | 0.39 |
| 1 | 0.94 | -0.48 | 0.68 | -0.11 | 0.03 | -0.38 |
| 2 | -0.29 | 1.71 | 0.66 | 0.08 | 0.78 | 1.67 |
| 3 | -0.52 | -0.43 | -0.76 | -0.21 | -0.42 | -0.48 |

These values are **standardized means**.

A value above zero indicates that the cluster is above the overall dataset average for that feature, while a value below zero indicates that it is below the overall dataset average.

---

## CISA Known Exploited Vulnerability Analysis

CISA KEV status provides an important external security indicator for interpreting the clusters.

The final K-Means model contains **1,653 CISA Known Exploited Vulnerabilities**.

Their distribution across clusters is:

| Cluster | CISA KEVs | Share of All KEVs |
|---|---:|---:|
| Cluster 0 | 960 | 58.08% |
| Cluster 1 | 548 | 33.15% |
| Cluster 2 | 0 | 0.00% |
| Cluster 3 | 145 | 8.77% |

A particularly important result is:

> **Cluster 0 contains only 1.76% of the total vulnerability population but contains 58.08% of all CISA Known Exploited Vulnerabilities.**

This indicates that the clustering process identified a small vulnerability group with disproportionately high known-exploitation relevance.

---

## Threat Intelligence Enrichment

After clustering, CVE IDs are attached back to the clustered records.

The clusters are then enriched using the second vulnerability corpus.

The enrichment adds:

```text
CVE ID
CWE
Vendor
Product
```

The final enriched dataset contains:

```text
346,232 rows
44 columns
```

This allows the machine-generated clusters to be interpreted from a cybersecurity and threat intelligence perspective.

---

## CWE Analysis

Generic CWE categories such as:

```text
NVD-CWE-Other
NVD-CWE-noinfo
```

are excluded from the final CWE visualizations so that specific vulnerability weakness patterns can be identified.

### Cluster 0

Top CWE patterns:

```text
CWE-119
CWE-22
CWE-78
```

### Cluster 1

Top CWE patterns:

```text
CWE-787
CWE-89
CWE-416
```

### Cluster 2

Top CWE patterns:

```text
CWE-79
CWE-119
CWE-89
```

### Cluster 3

Top CWE patterns:

```text
CWE-79
CWE-200
CWE-862
```

The differences in CWE distribution provide additional security context for understanding the vulnerability groups discovered by the clustering model.

---

## Vendor Analysis

Threat intelligence enrichment also identifies the vendors most frequently associated with vulnerabilities in each cluster.

### Cluster 0

```text
Microsoft
Apache
Adobe
Oracle
HP
```

### Cluster 1

```text
Google
Microsoft
Linux
Adobe
Apple
```

### Cluster 2

```text
Microsoft
Oracle
Apple
IBM
Cisco
```

### Cluster 3

```text
Linux
Google
IBM
Oracle
Microsoft
```

Vendor and product information can help translate statistical clusters into practical vulnerability remediation campaigns.

---

## Key Findings

The project produced several important findings:

- Vulnerabilities can be grouped using multiple technical and threat-related characteristics rather than severity alone.
- K-Means produced four distinct vulnerability profiles across the complete dataset.
- Cluster 0 represents only **1.76%** of vulnerabilities but contains **58.08% of all CISA KEVs**.
- Cluster 2 contains vulnerabilities with relatively high exploitability and older vulnerability age.
- Cluster 3 represents the largest vulnerability population and has lower standardized severity, impact, EPSS and vulnerability-age characteristics.
- CWE, vendor and product enrichment provides additional cybersecurity meaning to the statistical clusters.

---

## Project Structure

```text
VULNIQ/
│
├── data/
│   ├── raw/
│   │   ├── cve_cisa_epss_enriched_dataset.csv
│   │   └── cve_corpus.csv
│   │
│   └── processed/
│       ├── cve_cisa_epss_preprocessed.csv
│       ├── cve_feature_engineered.csv
│       ├── cve_selected_features.csv
│       ├── cve_encoded_scaled.csv
│       ├── cve_kmeans_k4_clustered.csv
│       ├── cve_kmeans_k4_with_ids.csv
│       └── cve_kmeans_k4_enriched.csv
│
├── src/
│   ├── 01_data_preprocessing.py
│   ├── 02_feature_engineering.py
│   ├── 03_feature_selection.py
│   ├── 04_encoding_scaling.py
│   ├── 05_kmeans_clustering.py
│   ├── 06_agglomerative_clustering.py
│   ├── 07_dbscan_clustering.py
│   ├── 08_threat_intelligence_enrichment.py
│   └── 09_results_visualization.py
│
├── outputs/
│   ├── charts/
│   └── results/
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Installation

### 1. Clone the repository

Clone the repository and move into the VULNIQ project directory.

### 2. Create a virtual environment

On Windows:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.venv\Scripts\activate
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

The main Python dependencies are:

```text
pandas
numpy
matplotlib
scikit-learn
```

---

## Preparing the Data

Download the datasets from:

[CVE, CISA KEV & EPSS Datasets on Kaggle](https://www.kaggle.com/datasets/francescomanzoni/vulnerability-management-datasets)

Place the required CSV files inside:

```text
data/raw/
```

The folder should contain:

```text
data/raw/
├── cve_cisa_epss_enriched_dataset.csv
└── cve_corpus.csv
```

---

## Running the Project

## Running the Project

Move into the source directory:

```powershell
cd src
```

The scripts should be executed sequentially because each stage uses datasets generated by the previous stages.

### 1. Data Preprocessing

```powershell
python 01_data_preprocessing.py
```

Performs initial data exploration and preprocessing, including missing-value handling and data quality checks.

### 2. Feature Engineering

```powershell
python 02_feature_engineering.py
```

Creates the `vulnerability_age_days` feature from the vulnerability publication date.

### 3. Feature Selection

```powershell
python 03_feature_selection.py
```

Performs variance and correlation analysis and selects the final features used for clustering.

### 4. Encoding and Scaling

```powershell
python 04_encoding_scaling.py
```

Applies One-Hot Encoding to categorical features and StandardScaler to numerical features.

### 5. K-Means Clustering

```powershell
python 05_kmeans_clustering.py
```

Evaluates K-Means clustering and creates the final K-Means model using **K=4**.

### 6. Agglomerative Clustering

```powershell
python 06_agglomerative_clustering.py
```

Evaluates Agglomerative Clustering on a representative 20,000-row sample and compares different values of K.

### 7. DBSCAN Clustering

```powershell
python 07_dbscan_clustering.py
```

Evaluates DBSCAN using a representative 20,000-row sample, performs K-distance analysis, and tests different `eps` values.

### 8. Threat Intelligence Enrichment

```powershell
python 08_threat_intelligence_enrichment.py
```

Attaches CVE IDs to the final K-Means clusters and enriches the results with:

- CWE
- Vendor
- Product

The enrichment information is extracted from the threat intelligence dataset `cve_corpus.csv`.

### 9. Results and Visualization

```powershell
python 09_results_visualization.py
```

Generates the final analysis and visualizations, including:

- Cluster distribution
- Numerical cluster profiles
- CISA KEV distribution
- Top CWE patterns by cluster
- Top vendors by cluster

---

## Technologies Used

- Python
- Pandas
- NumPy
- scikit-learn
- Matplotlib
- K-Means Clustering
- Agglomerative Clustering
- DBSCAN
- CVSS vulnerability metrics
- EPSS exploitation probability
- CISA KEV threat intelligence
- CWE and CPE vulnerability information

---

## Key Result

The final **K-Means K=4** model identified four distinct vulnerability profiles across **346,232 CVEs**.

One of the most significant findings was **Cluster 0**:

- Represents only **1.76%** of the vulnerability dataset
- Contains **960 CISA Known Exploited Vulnerabilities**
- Accounts for **58.08% of all CISA KEVs** in the dataset

This demonstrates that multidimensional vulnerability profiling can identify relatively small groups containing a disproportionately high concentration of known exploited vulnerabilities.

---

## Conclusion

VULNIQ demonstrates an end-to-end machine learning workflow for vulnerability profiling.

Instead of relying only on CVSS severity, the project combines multiple vulnerability characteristics including severity, exploitability, impact, EPSS exploitation probability, CISA KEV status, attack characteristics, and vulnerability age.

Three unsupervised clustering approaches — **K-Means, Agglomerative Clustering, and DBSCAN** — were evaluated. K-Means with **K=4** was selected as the final model because it provided four distinct and interpretable vulnerability profiles suitable for further threat intelligence analysis.

The resulting clusters were enriched using CWE, vendor, and product information, allowing the statistical groups to be interpreted from a cybersecurity perspective.

The results demonstrate how unsupervised machine learning and threat intelligence enrichment can complement traditional severity-based vulnerability analysis and support more targeted vulnerability profiling and remediation planning.
