import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import time

from sklearn.model_selection import train_test_split
from sklearn.neighbors import NearestNeighbors
from sklearn.cluster import DBSCAN
from sklearn.metrics import silhouette_score


# ==========================================
# 1. Load Dataset
# ==========================================

dataset = pd.read_csv(
    "../data/processed/cve_encoded_scaled.csv"
)

print("\nFull dataset shape:")
print(dataset.shape)


# ==========================================
# 2. Create the same 20,000-row sample
# ==========================================

sample, _ = train_test_split(
    dataset,
    train_size=20000,
    stratify=dataset['cisa_kev'],
    random_state=42
)

print("\nDBSCAN sample created successfully.")
print("Sample shape:", sample.shape)

print("\nCISA KEV Distribution:")
print(
    (sample['cisa_kev'].value_counts(normalize=True) * 100)
    .round(3)
)


# ==========================================
# 3. K-Distance Plot for DBSCAN
# ==========================================

min_samples = 5

neighbors = NearestNeighbors(
    n_neighbors=min_samples
)

neighbors_fit = neighbors.fit(sample)

distances, indices = neighbors_fit.kneighbors(sample)

# Distance to the 5th nearest neighbour
k_distances = distances[:, -1]

# Sort distances
k_distances = np.sort(k_distances)

print("\nK-Distance Statistics:")
print("Minimum:", round(k_distances.min(), 3))
print("Median :", round(np.median(k_distances), 3))
print("90th percentile:", round(np.percentile(k_distances, 90), 3))
print("95th percentile:", round(np.percentile(k_distances, 95), 3))
print("99th percentile:", round(np.percentile(k_distances, 99), 3))
print("Maximum:", round(k_distances.max(), 3))

# Plot
plt.figure(figsize=(8, 5))

plt.plot(k_distances)

plt.title("5-Nearest Neighbor Distance Plot")
plt.xlabel("Data Points Sorted by Distance")
plt.ylabel("5th Nearest Neighbor Distance")

plt.grid(True)
plt.tight_layout()
plt.show()


# ==========================================
# 4. Test Smaller DBSCAN eps Values
# ==========================================

eps_values = [0.75, 1.0, 1.25, 1.5]

print("\nTesting DBSCAN Parameters...")

for eps in eps_values:

    print(f"\n--- eps = {eps}, min_samples = 5 ---")

    start_time = time.time()

    dbscan = DBSCAN(
        eps=eps,
        min_samples=5,
        n_jobs=-1
    )

    labels = dbscan.fit_predict(sample)

    elapsed_time = time.time() - start_time

    # DBSCAN labels noise as -1
    n_clusters = (
        len(set(labels))
        - (1 if -1 in labels else 0)
    )

    n_noise = np.sum(labels == -1)

    noise_percentage = (
        n_noise / len(labels)
    ) * 100

    print("Number of clusters:", n_clusters)
    print("Noise points:", n_noise)
    print(
        f"Noise percentage: "
        f"{noise_percentage:.2f}%"
    )
    print(
        f"Time taken: "
        f"{elapsed_time:.2f} seconds"
    )


# ==========================================
# 5. Test Larger eps Values
# ==========================================

eps_values = [1.75, 2.0, 2.25, 2.5]

for eps in eps_values:

    print(f"\n--- eps = {eps}, min_samples = 5 ---")

    start_time = time.time()

    dbscan = DBSCAN(
        eps=eps,
        min_samples=5,
        n_jobs=-1
    )

    labels = dbscan.fit_predict(sample)

    elapsed_time = time.time() - start_time

    n_clusters = (
        len(set(labels))
        - (1 if -1 in labels else 0)
    )

    n_noise = np.sum(labels == -1)

    noise_percentage = (
        n_noise / len(labels)
    ) * 100

    print("Number of clusters:", n_clusters)
    print("Noise points:", n_noise)
    print(
        f"Noise percentage: "
        f"{noise_percentage:.2f}%"
    )
    print(
        f"Time taken: "
        f"{elapsed_time:.2f} seconds"
    )


# ==========================================
# 6. Evaluate Selected DBSCAN Configurations
# ==========================================

eps_values = [1.75, 2.0, 2.25]

print(
    "\nEvaluating selected "
    "DBSCAN configurations..."
)

for eps in eps_values:

    dbscan = DBSCAN(
        eps=eps,
        min_samples=5,
        n_jobs=-1
    )

    labels = dbscan.fit_predict(sample)

    n_clusters = (
        len(set(labels))
        - (1 if -1 in labels else 0)
    )

    n_noise = np.sum(labels == -1)

    # Exclude noise points (-1)
    # from silhouette calculation
    non_noise_mask = labels != -1

    filtered_sample = sample[non_noise_mask]
    filtered_labels = labels[non_noise_mask]

    score = silhouette_score(
        filtered_sample,
        filtered_labels,
        sample_size=min(
            5000,
            len(filtered_sample)
        ),
        random_state=42
    )

    print(f"\neps = {eps}")
    print(f"Clusters: {n_clusters}")
    print(
        f"Noise: {n_noise} "
        f"({n_noise / len(sample) * 100:.2f}%)"
    )
    print(
        f"Silhouette Score: "
        f"{score:.4f}"
    )


# ==========================================
# 7. Final DBSCAN Model
# ==========================================

dbscan_final = DBSCAN(
    eps=2.25,
    min_samples=5,
    n_jobs=-1
)

dbscan_labels = dbscan_final.fit_predict(sample)

dbscan_data = sample.copy()
dbscan_data['cluster'] = dbscan_labels


# ==========================================
# 8. Cluster Distribution
# ==========================================

print("\nFinal DBSCAN Cluster Distribution:")

distribution = (
    dbscan_data['cluster']
    .value_counts()
    .sort_index()
)

distribution_df = pd.DataFrame({
    'Count': distribution,
    'Percentage': (
        distribution / len(dbscan_data) * 100
    ).round(2)
})

print(distribution_df)


# ==========================================
# 9. Numerical Cluster Profile
# ==========================================

numeric_features = [
    'base_score',
    'exploitability_score',
    'impact_score',
    'epss_score',
    'epss_perc',
    'vulnerability_age_days'
]

numeric_profile = (
    dbscan_data
    .groupby('cluster')[numeric_features]
    .mean()
    .round(3)
)

print("\nDBSCAN Numerical Cluster Profile:")
print(numeric_profile)


# ==========================================
# 10. CISA KEV Profile
# ==========================================

kev_profile = (
    dbscan_data
    .groupby('cluster')['cisa_kev']
    .agg(
        Total_CVEs='count',
        KEV_Count='sum',
        KEV_Percentage='mean'
    )
)

kev_profile['KEV_Percentage'] = (
    kev_profile['KEV_Percentage'] * 100
).round(2)

print("\nDBSCAN CISA KEV Profile:")
print(kev_profile)