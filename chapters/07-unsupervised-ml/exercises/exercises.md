# Chapter 07 Exercises: Unsupervised Machine Learning

These exercises use publicly available data from USAspending.gov and synthetic datasets. No CAC required. Work through them in order — each builds on the last.

---

## Exercise 1: K-means Cluster Selection on Procurement Data

**Scenario:** You have pulled 10,000 Navy contract awards from USAspending (NAICS codes 541512, 541511, 541519) for FY2022–2024. Your program office wants to understand whether there are distinct "types" of Navy IT contracts — not based on NAICS code, but based on the actual award characteristics.

**Task:**

1. Pull at least 500 contract records from USAspending using the techniques from Chapter 03. Features to include:
   - `Award Amount` (obligated dollars)
   - `modification_count` (number of modifications)
   - Period of performance in days
   - Whether the award is a definitive contract or task order

2. Apply the feature engineering needed before clustering:
   - Log-transform the obligation amount (why?)
   - Scale all features with `RobustScaler`
   - Handle missing values

3. Run K-means for k = 2 through 12. Plot silhouette scores versus k.

4. Select the best k based on your silhouette plot. Run `characterize_clusters()` and write a 2-sentence description of each cluster.

5. Run the same data through DBSCAN. How many "noise" points (label = -1) does DBSCAN find? Describe one of the outlier contracts.

**Acceptance criteria:**
- Silhouette plot is interpretable and shows at least 10 values of k
- Each cluster has a human-readable description based on its feature medians
- The DBSCAN outliers are characterized (not just counted)

---

## Exercise 2: Fiscal-Calendar Anomaly Detection

**Scenario:** You are building an anomaly detection system for a Navy financial management office. The data is DoD GFEBS-style financial transactions (use the synthetic generator below to create a dataset). Your first attempt flagged 40% of transactions in September as anomalies. The financial analyst on your team says "those are all normal Q4 year-end activity."

**Generate synthetic data:**

```python
import numpy as np
import pandas as pd

np.random.seed(42)
n = 10_000
dates = pd.date_range("2022-10-01", "2024-09-30", periods=n)

# Q4 (Jul-Sep) has 3x normal transaction volume and higher amounts
month = pd.DatetimeIndex(dates).month
is_q4 = (month >= 7) & (month <= 9)

df = pd.DataFrame({
    "transaction_date": dates,
    "obligation_amount": np.where(
        is_q4,
        np.random.lognormal(13.5, 0.7, n),  # Q4: larger amounts
        np.random.lognormal(11.5, 0.9, n),  # Other quarters: normal
    ),
    "line_item_count": np.where(
        is_q4,
        np.random.poisson(12, n),
        np.random.poisson(4, n),
    ),
    "days_to_close": np.random.normal(45, 20, n).clip(1, 365),
    "modification_count": np.random.poisson(3, n),
})

# Inject 50 true anomalies (unusual at any time of year)
anomaly_idx = np.random.choice(n, 50, replace=False)
df.loc[anomaly_idx, "obligation_amount"] *= 50
df.loc[anomaly_idx, "modification_count"] = np.random.poisson(30, 50)
```

**Task:**

1. Run a naive Isolation Forest (no fiscal quarter stratification) with contamination=0.01. How many of your flagged anomalies fall in Q4 (months July-September)? What percentage of Q4 transactions are flagged?

2. Run the fiscal-quarter-aware Isolation Forest from the chapter code examples. How does the Q4 flag rate change?

3. Of the 50 true injected anomalies, how many does each approach catch? Calculate precision and recall for both approaches. Which performs better?

4. Produce a validation review sheet (using `anomaly_validation_sample()`) for 30 records. Manually review each record in the sample. What are the most common false positive patterns?

**Acceptance criteria:**
- Both models implemented and compared quantitatively
- Precision and recall calculated for both approaches
- The false positive patterns are described clearly

---

## Exercise 3: Topic Modeling on Federal Register Text

**Scenario:** The Federal Register is publicly available and contains thousands of notices, rules, and proposed rules from every federal agency. Your agency wants to understand what topics dominate recent DoD-related Federal Register entries.

**Data source:** The Federal Register API is publicly available at `https://www.federalregister.gov/api/v1/`. No authentication required.

**Task:**

1. Pull at least 200 documents from the Federal Register API filtered to agency "DEFENSE DEPARTMENT" for 2023-2024:

```python
import requests

url = "https://www.federalregister.gov/api/v1/documents.json"
params = {
    "conditions[agencies][]": "defense-department",
    "conditions[publication_date][gte]": "2023-01-01",
    "conditions[publication_date][lte]": "2024-12-31",
    "fields[]": ["title", "abstract", "document_number", "publication_date"],
    "per_page": 100,
    "page": 1,
}
# Paginate to get at least 200 documents
```

2. Combine the `title` and `abstract` fields as your document text. Apply `preprocess_government_text()`.

3. Run LDA with n_topics = 8. Print the top 10 words for each topic.

4. Name each topic in 5 words or fewer based on the top words. Show 2 representative document titles from each topic.

5. What is the most common topic? What is the least common topic? Does this distribution surprise you?

**Acceptance criteria:**
- At least 200 documents retrieved
- All 8 topics are named (not labeled "Topic 0", "Topic 1", etc.)
- Representative documents validate the topic names

---

## Exercise 4: PCA + Clustering Pipeline

**Scenario:** You have a DoD logistics dataset with 150 features per item (National Stock Number characteristics, failure rates, demand patterns, supply chain metrics). Running K-means directly on 150 features produces poor results. You need a dimensionality reduction step.

**Generate synthetic data:**

```python
import numpy as np
import pandas as pd
from sklearn.datasets import make_classification

# 5,000 NSNs, 150 features, 4 natural clusters
X_raw, y_true = make_classification(
    n_samples=5_000,
    n_features=150,
    n_informative=20,
    n_redundant=30,
    n_clusters_per_class=1,
    n_classes=4,
    random_state=42,
)

df = pd.DataFrame(X_raw, columns=[f"feature_{i}" for i in range(150)])
df["true_cluster"] = y_true  # Only for validation — pretend you don't have this
```

**Task:**

1. Run K-means directly on the 150 features (k=4). Calculate silhouette score.

2. Run PCA on the 150 features. How many components capture 90% of variance?

3. Run K-means on the PCA-reduced features. Calculate silhouette score. Compare to step 1.

4. Run UMAP to reduce to 2 dimensions. Create a scatter plot colored by cluster assignment.

5. Using `y_true` as a ground truth (which you would not have in production), calculate the Adjusted Rand Index for both the direct K-means and the PCA + K-means approaches. Which recovers the true structure better?

**Acceptance criteria:**
- PCA explained variance curve is plotted
- Both K-means runs are compared with silhouette score AND Adjusted Rand Index
- UMAP scatter plot shows clear cluster separation (or explains why it does not)

---

## Exercise 5: DBSCAN for Ship Maintenance Outliers

**Scenario:** You have access to a synthetic Navy ship maintenance dataset with work order attributes. You want to find work orders that are unusual — not in a fraudulent sense, but in the sense that they may represent edge cases requiring special handling (unusual equipment, unusual failure modes, or data entry errors worth reviewing).

**Generate data:**

```python
import numpy as np
import pandas as pd

np.random.seed(99)
n = 3_000

df = pd.DataFrame({
    "wo_id": [f"WO{i:05d}" for i in range(n)],
    "equipment_age_years": np.random.exponential(5, n).clip(0, 30),
    "parts_cost_usd": np.random.lognormal(8, 1.5, n),
    "labor_hours": np.random.lognormal(3, 0.8, n),
    "days_overdue": np.random.exponential(10, n),
    "prior_failure_count": np.random.poisson(2, n),
})

# Inject 30 genuine outliers: very old equipment with extreme costs
outlier_idx = np.random.choice(n, 30, replace=False)
df.loc[outlier_idx, "equipment_age_years"] = np.random.uniform(25, 30, 30)
df.loc[outlier_idx, "parts_cost_usd"] *= 20
df.loc[outlier_idx, "labor_hours"] *= 8
```

**Task:**

1. Run `run_dbscan()` on this dataset with `min_samples=5`. Try three values of `eps`: auto-estimated, auto/2, and auto*2. How does the number of noise points change?

2. For the eps value that produces the most interpretable results, examine the noise points (cluster = -1). How do they differ from the main cluster on each feature?

3. Generate the cluster validation report. Present it as if you were showing it to a maintenance officer — what questions would you ask them?

4. Compare DBSCAN outliers to Isolation Forest outliers on the same dataset. Do they flag the same records? What percentage of the injected 30 outliers does each method recover?

**Acceptance criteria:**
- Three DBSCAN runs with different eps values compared
- Outlier characterization described in terms a maintenance officer would understand
- Overlap between DBSCAN and Isolation Forest outliers calculated

---

See [solutions/solutions.md](solutions/solutions.md) for worked solutions.
