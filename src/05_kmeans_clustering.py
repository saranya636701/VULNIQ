import pandas as pd

# Load encoded & scaled dataset
dataset = pd.read_csv(
    "../data/processed/cve_encoded_scaled.csv"
)

print("Dataset loaded successfully.")

print("\nShape of dataset:")
print(dataset.shape)

print("\nFirst 5 rows:")
print(dataset.head())

print("\nData Types:")
print(dataset.dtypes)

from sklearn.cluster import KMeans
import time

start = time.time()

kmeans = KMeans(
    n_clusters=2,
    random_state=42,
    n_init=10
)

kmeans.fit(dataset)

end = time.time()

print("\nK-Means completed successfully.")
print(f"Time taken: {end - start:.2f} seconds")

print("\nWCSS:")
print(kmeans.inertia_)

import matplotlib.pyplot as plt

# Store WCSS values
wcss = []

# Try K values from 2 to 10
for k in range(2, 11):

    print(f"Training K-Means with K = {k}")

    kmeans = KMeans(
        n_clusters=k,
        random_state=42,
        n_init=10
    )

    kmeans.fit(dataset)

    wcss.append(kmeans.inertia_)

print("\nWCSS Values:")
for k, value in zip(range(2, 11), wcss):
    print(f"K = {k}: {value}")

# Plot Elbow Curve
plt.figure(figsize=(8,5))

plt.plot(range(2,11), wcss, marker='o')

plt.title("Elbow Method for Optimal K")
plt.xlabel("Number of Clusters (K)")
plt.ylabel("WCSS")

plt.grid(True)

plt.show()

# Calculate Silhouette Scores

from sklearn.metrics import silhouette_score

print("\nCalculating Silhouette Scores...")

silhouette_scores = []

for k in range(2, 11):

    print(f"Calculating Silhouette Score for K = {k}")

    kmeans = KMeans(
        n_clusters=k,
        random_state=42,
        n_init=10
    )

    labels = kmeans.fit_predict(dataset)

    score = silhouette_score(
        dataset,
        labels,
        sample_size=5000,
        random_state=42
    )

    silhouette_scores.append(score)

print("\nSilhouette Scores:")

for k, score in zip(range(2, 11), silhouette_scores):
    print(f"K = {k}: {score:.4f}")

plt.show()


# ==========================================
# Compare Cluster Distribution: K=2 vs K=4
# ==========================================

print("\nCluster Distribution Comparison")

for k in [2, 4]:

    print(f"\n{'='*40}")
    print(f"K = {k}")
    print(f"{'='*40}")

    kmeans = KMeans(
        n_clusters=k,
        random_state=42,
        n_init=10
    )

    labels = kmeans.fit_predict(dataset)

    # Number of vulnerabilities in each cluster
    cluster_counts = pd.Series(labels).value_counts().sort_index()

    # Percentage of vulnerabilities in each cluster
    cluster_percentages = (
        cluster_counts / len(dataset) * 100
    ).round(2)

    result = pd.DataFrame({
        'Count': cluster_counts,
        'Percentage': cluster_percentages
    })

    print(result)

# Create K-Means model with K = 4

kmeans_k4 = KMeans(
    n_clusters=4,
    random_state=42,
    n_init=10
)

# Generate cluster labels
labels_k4 = kmeans_k4.fit_predict(dataset)


# Attach cluster labels to a copy of the dataset
dataset_k4 = dataset.copy()
dataset_k4['cluster'] = labels_k4

print("\nFirst 10 rows with K=4 cluster labels:")

print(
    dataset_k4[
        ['base_score', 'epss_score', 'cisa_kev', 'cluster']
    ].head(10)
)


# Numerical profile of K=4 clusters

numeric_features = [
    'base_score',
    'exploitability_score',
    'impact_score',
    'epss_score',
    'epss_perc',
    'vulnerability_age_days'
]

print("\nNumerical Profile of K=4 Clusters:")

cluster_profile = (
    dataset_k4
    .groupby('cluster')[numeric_features]
    .mean()
    .round(3)
)

print(cluster_profile)

# ==========================================
# CISA KEV Profile by Cluster
# ==========================================

print("\nCISA KEV Profile of K=4 Clusters:")

kev_profile = dataset_k4.groupby('cluster')['cisa_kev'].agg(
    Total_CVEs='count',
    KEV_Count='sum',
    KEV_Percentage='mean'
)

# Convert proportion to percentage
kev_profile['KEV_Percentage'] = (
    kev_profile['KEV_Percentage'] * 100
).round(2)

print(kev_profile)

# ==========================================
# Attack Vector Profile by Cluster
# ==========================================

attack_vector_columns = [
    'attack_vector_ADJACENT_NETWORK',
    'attack_vector_LOCAL',
    'attack_vector_NETWORK',
    'attack_vector_PHYSICAL'
]

print("\nAttack Vector Profile of K=4 Clusters:")

attack_vector_profile = (
    dataset_k4
    .groupby('cluster')[attack_vector_columns]
    .mean()
    .multiply(100)
    .round(2)
)

print(attack_vector_profile)

# ==========================================
# Attack Complexity Profile by Cluster
# ==========================================

attack_complexity_columns = [
    'attack_complexity_HIGH',
    'attack_complexity_LOW',
    'attack_complexity_MEDIUM'
]

print("\nAttack Complexity Profile of K=4 Clusters:")

attack_complexity_profile = (
    dataset_k4
    .groupby('cluster')[attack_complexity_columns]
    .mean()
    .multiply(100)
    .round(2)
)

print(attack_complexity_profile)

# ==========================================
# Privileges Required Profile by Cluster
# ==========================================

privilege_columns = [
    'privileges_required_HIGH',
    'privileges_required_LOW',
    'privileges_required_NONE',
    'privileges_required_NOT_DEFINED'
]

print("\nPrivileges Required Profile of K=4 Clusters:")

privilege_profile = (
    dataset_k4
    .groupby('cluster')[privilege_columns]
    .mean()
    .multiply(100)
    .round(2)
)

print(privilege_profile)

# ==========================================
# User Interaction Profile by Cluster
# ==========================================

user_interaction_columns = [
    'user_interaction_NONE',
    'user_interaction_NOT_DEFINED',
    'user_interaction_REQUIRED'
]

print("\nUser Interaction Profile of K=4 Clusters:")

user_interaction_profile = (
    dataset_k4
    .groupby('cluster')[user_interaction_columns]
    .mean()
    .multiply(100)
    .round(2)
)

print(user_interaction_profile)

# ==========================================
# Scope Profile by Cluster
# ==========================================

scope_columns = [
    'scope_CHANGED',
    'scope_NOT_DEFINED',
    'scope_UNCHANGED'
]

print("\nScope Profile of K=4 Clusters:")

scope_profile = (
    dataset_k4
    .groupby('cluster')[scope_columns]
    .mean()
    .multiply(100)
    .round(2)
)

print(scope_profile)

# ==========================================
# EXPERIMENT:
# Remove NOT_DEFINED indicators from clustering
# ==========================================

columns_to_remove = [
    'privileges_required_NOT_DEFINED',
    'user_interaction_NOT_DEFINED',
    'scope_NOT_DEFINED'
]

dataset_experiment = dataset.drop(
    columns=columns_to_remove
)

print("\nOriginal dataset shape:")
print(dataset.shape)

print("\nExperimental dataset shape:")
print(dataset_experiment.shape)

print("\nRemoved columns:")
print(columns_to_remove)

# ==========================================
# Elbow Method - Experimental Dataset
# ==========================================

print("\nRunning Elbow Method on Experimental Dataset...")

wcss_experiment = []

for k in range(2, 11):

    print(f"Training Experimental K-Means with K = {k}")

    kmeans_exp = KMeans(
        n_clusters=k,
        random_state=42,
        n_init=10
    )

    kmeans_exp.fit(dataset_experiment)

    wcss_experiment.append(kmeans_exp.inertia_)

print("\nExperimental WCSS Values:")

for k, value in zip(range(2, 11), wcss_experiment):
    print(f"K = {k}: {value}")

#Experimental silhouette scores

from sklearn.metrics import silhouette_score

print("\nCalculating Experimental Silhouette Scores...")

silhouette_scores_experiment = []

for k in range(2, 11):

    print(f"Calculating Experimental Silhouette Score for K = {k}")

    kmeans_exp = KMeans(
        n_clusters=k,
        random_state=42,
        n_init=10
    )

    labels_exp = kmeans_exp.fit_predict(dataset_experiment)

    score = silhouette_score(
        dataset_experiment,
        labels_exp,
        sample_size=5000,
        random_state=42
    )

    silhouette_scores_experiment.append(score)

print("\nExperimental Silhouette Scores:")

for k, score in zip(range(2, 11), silhouette_scores_experiment):
    print(f"K = {k}: {score:.4f}")

# ==========================================
# CIA Impact Profile by Cluster
# ==========================================

impact_types = [
    'COMPLETE',
    'HIGH',
    'LOW',
    'NONE',
    'PARTIAL'
]

# Confidentiality
conf_columns = [
    f'confidentiality_impact_{x}' for x in impact_types
]

conf_profile = (
    dataset_k4.groupby('cluster')[conf_columns]
    .mean()
    .multiply(100)
    .round(2)
)

# Rename columns for clean display
conf_profile.columns = impact_types

print("\nConfidentiality Impact (%)")
print(conf_profile)


# Integrity
integrity_columns = [
    f'integrity_impact_{x}' for x in impact_types
]

integrity_profile = (
    dataset_k4.groupby('cluster')[integrity_columns]
    .mean()
    .multiply(100)
    .round(2)
)

integrity_profile.columns = impact_types

print("\nIntegrity Impact (%)")
print(integrity_profile)


# Availability
availability_columns = [
    f'availability_impact_{x}' for x in impact_types
]

availability_profile = (
    dataset_k4.groupby('cluster')[availability_columns]
    .mean()
    .multiply(100)
    .round(2)
)

availability_profile.columns = impact_types

print("\nAvailability Impact (%)")
print(availability_profile)

# ==========================================
# Create and Profile K=2 Model
# ==========================================

kmeans_k2 = KMeans(
    n_clusters=2,
    random_state=42,
    n_init=10
)

labels_k2 = kmeans_k2.fit_predict(dataset)

dataset_k2 = dataset.copy()
dataset_k2['cluster'] = labels_k2

numeric_features = [
    'base_score',
    'exploitability_score',
    'impact_score',
    'epss_score',
    'epss_perc',
    'vulnerability_age_days'
]

k2_numeric_profile = (
    dataset_k2
    .groupby('cluster')[numeric_features]
    .mean()
    .round(3)
)

print("\nK=2 Numerical Cluster Profile:")
print(k2_numeric_profile)

print("\nK=2 CISA KEV Profile:")

k2_kev_profile = dataset_k2.groupby('cluster')['cisa_kev'].agg(
    Total_CVEs='count',
    KEV_Count='sum',
    KEV_Percentage='mean'
)

k2_kev_profile['KEV_Percentage'] = (
    k2_kev_profile['KEV_Percentage'] * 100
).round(2)

print(k2_kev_profile)

# ==========================================
# Final K-Means Model - K = 4
# ==========================================

from sklearn.cluster import KMeans

final_kmeans = KMeans(
    n_clusters=4,
    random_state=42,
    n_init=10
)

final_labels = final_kmeans.fit_predict(dataset)

# Create final clustered dataset
final_clustered_data = dataset.copy()

final_clustered_data['cluster'] = final_labels

print("\nFinal K=4 model created successfully.")

print("\nCluster Distribution:")
print(
    final_clustered_data['cluster']
    .value_counts()
    .sort_index()
)

# Save
final_clustered_data.to_csv(
    "../data/processed/cve_kmeans_k4_clustered.csv",
    index=False
)

print("\nSaved as: ../data/processed/cve_kmeans_k4_clustered.csv")