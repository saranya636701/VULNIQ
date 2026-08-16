import pandas as pd
import time

from sklearn.model_selection import train_test_split
from sklearn.cluster import AgglomerativeClustering
from sklearn.metrics import silhouette_score


# ==========================================
# 1. Load encoded and scaled dataset
# ==========================================

dataset = pd.read_csv(
    "../data/processed/cve_encoded_scaled.csv"
)

print("\nFull dataset shape:")
print(dataset.shape)


# ==========================================
# 2. Create 20,000-row representative sample
# Stratified by CISA KEV
# ==========================================

sample, _ = train_test_split(
    dataset,
    train_size=20000,
    stratify=dataset['cisa_kev'],
    random_state=42
)

print("\nSample shape:")
print(sample.shape)


# ==========================================
# 3. Compare CISA KEV distribution
# ==========================================

print("\nFull Dataset - CISA KEV Distribution (%):")

print(
    (dataset['cisa_kev'].value_counts(normalize=True) * 100)
    .round(3)
)

print("\nSample - CISA KEV Distribution (%):")

print(
    (sample['cisa_kev'].value_counts(normalize=True) * 100)
    .round(3)
)


# ==========================================
# 4. Compare Numerical Feature Distributions
# ==========================================

numeric_features = [
    'base_score',
    'exploitability_score',
    'impact_score',
    'epss_score',
    'epss_perc',
    'vulnerability_age_days'
]

comparison = pd.DataFrame({
    'Full_Mean': dataset[numeric_features].mean(),
    'Sample_Mean': sample[numeric_features].mean(),
    'Full_Std': dataset[numeric_features].std(),
    'Sample_Std': sample[numeric_features].std()
})

print("\nNumerical Distribution Comparison:")
print(comparison.round(3))


# ==========================================
# 5. Agglomerative Clustering with K = 4
# ==========================================

print("\nRunning Agglomerative Clustering with K = 4...")

start_time = time.time()

agg_model = AgglomerativeClustering(
    n_clusters=4,
    linkage='ward'
)

agg_labels = agg_model.fit_predict(sample)

end_time = time.time()

print("\nAgglomerative Clustering completed successfully.")

print(
    f"Time taken: "
    f"{end_time - start_time:.2f} seconds"
)


# ==========================================
# 6. Cluster Distribution
# ==========================================

print("\nCluster Distribution:")

cluster_counts = (
    pd.Series(agg_labels)
    .value_counts()
    .sort_index()
)

cluster_percentages = (
    cluster_counts / len(sample) * 100
).round(2)

cluster_distribution = pd.DataFrame({
    'Count': cluster_counts,
    'Percentage': cluster_percentages
})

print(cluster_distribution)


# ==========================================
# 7. K=4 Silhouette Score
# ==========================================

print("\nCalculating Agglomerative Silhouette Score...")

agg_silhouette = silhouette_score(
    sample,
    agg_labels,
    sample_size=5000,
    random_state=42
)

print(
    f"Agglomerative Silhouette Score: "
    f"{agg_silhouette:.4f}"
)


# ==========================================
# 8. Find Best K for Agglomerative Clustering
# ==========================================

print(
    "\nTesting different K values "
    "for Agglomerative Clustering..."
)

agg_scores = []

for k in range(2, 7):

    print(f"\nTesting K = {k}")

    start_time = time.time()

    model = AgglomerativeClustering(
        n_clusters=k,
        linkage='ward'
    )

    labels = model.fit_predict(sample)

    score = silhouette_score(
        sample,
        labels,
        sample_size=5000,
        random_state=42
    )

    elapsed_time = time.time() - start_time

    agg_scores.append(score)

    print(f"Silhouette Score: {score:.4f}")
    print(f"Time: {elapsed_time:.2f} seconds")


print("\nAgglomerative Silhouette Scores:")

for k, score in zip(range(2, 7), agg_scores):
    print(f"K = {k}: {score:.4f}")