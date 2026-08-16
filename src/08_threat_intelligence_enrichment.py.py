import pandas as pd
import ast


# ==========================================
# 1. Load Datasets
# ==========================================

# Load original feature-engineered dataset
original = pd.read_csv(
    "../data/processed/cve_feature_engineered.csv"
)

# Load final clustered dataset
clustered = pd.read_csv(
    "../data/processed/cve_kmeans_k4_clustered.csv"
)

print("Original dataset:", original.shape)
print("Clustered dataset:", clustered.shape)

print("\nFirst 5 CVE IDs:")
print(original['cve_id'].head())

print("\nCluster labels:")
print(clustered['cluster'].head())


# ==========================================
# 2. Attach CVE IDs
# ==========================================

clustered.insert(
    0,
    'cve_id',
    original['cve_id'].values
)

print("\nClustered dataset with CVE IDs:")
print(clustered[['cve_id', 'cluster']].head())

print("\nShape:")
print(clustered.shape)


# ==========================================
# 3. Save Clustered Dataset with CVE IDs
# ==========================================

clustered.to_csv(
    "../data/processed/cve_kmeans_k4_with_ids.csv",
    index=False
)

print("\nSaved as: cve_kmeans_k4_with_ids.csv")


# ==========================================
# 4. Load Threat Intelligence Dataset
# ==========================================

threat_data = pd.read_csv(
    "../data/raw/cve_corpus.csv"
)

print("\nThreat Intelligence Dataset:")
print(threat_data.shape)

print("\nColumns:")
print(threat_data.columns.tolist())

print("\nMissing Values:")
print(threat_data.isnull().sum())

print("\nFirst 5 CWE values:")
print(threat_data['cwe_data'].head())

print("\nFirst 5 CPE values:")
print(threat_data['cpe_data'].head())


# ==========================================
# 5. Parse CWE and CPE Data
# ==========================================

# Convert string representations of lists into Python lists
threat_data['cwe_list'] = threat_data['cwe_data'].apply(
    ast.literal_eval
)

threat_data['cpe_list'] = threat_data['cpe_data'].apply(
    ast.literal_eval
)


# Extract first CWE
threat_data['cwe'] = threat_data['cwe_list'].apply(
    lambda x: x[0] if len(x) > 0 else None
)


# Extract vendor and product from first CPE
def extract_cpe(cpe_list):

    if len(cpe_list) == 0:
        return pd.Series([None, None])

    parts = cpe_list[0].split(':')

    if len(parts) >= 5:
        vendor = parts[3]
        product = parts[4]

        return pd.Series([
            vendor,
            product
        ])

    return pd.Series([None, None])


threat_data[['vendor', 'product']] = (
    threat_data['cpe_list'].apply(
        extract_cpe
    )
)


print("\nParsed Threat Intelligence:")

print(
    threat_data[
        ['cve_id', 'cwe', 'vendor', 'product']
    ].head(10)
)


# ==========================================
# 6. Check Enrichment Quality
# ==========================================

print(
    "\nUnique CWE values:",
    threat_data['cwe'].nunique()
)

print(
    "Unique Vendors:",
    threat_data['vendor'].nunique()
)

print(
    "Unique Products:",
    threat_data['product'].nunique()
)

print("\nTop 15 CWE values:")
print(
    threat_data['cwe']
    .value_counts()
    .head(15)
)

print("\nTop 15 Vendors:")
print(
    threat_data['vendor']
    .value_counts()
    .head(15)
)

print("\nTop 15 Products:")
print(
    threat_data['product']
    .value_counts()
    .head(15)
)


# ==========================================
# 7. Merge Threat Intelligence with Clusters
# ==========================================

enrichment_data = threat_data[
    ['cve_id', 'cwe', 'vendor', 'product']
].copy()

final_enriched = clustered.merge(
    enrichment_data,
    on='cve_id',
    how='left'
)

print("\nFinal Enriched Dataset Shape:")
print(final_enriched.shape)

print("\nMissing Enrichment Values:")

print(
    final_enriched[
        ['cwe', 'vendor', 'product']
    ].isnull().sum()
)

print("\nFirst 10 Enriched Records:")

print(
    final_enriched[
        [
            'cve_id',
            'cluster',
            'cwe',
            'vendor',
            'product'
        ]
    ].head(10)
)


# ==========================================
# 8. Save Final Enriched Dataset
# ==========================================

final_enriched.to_csv(
    "../data/processed/cve_kmeans_k4_enriched.csv",
    index=False
)

print("\nFinal enriched dataset saved successfully.")
print("File: cve_kmeans_k4_enriched.csv")


# ==========================================
# 9. Threat Intelligence Cluster Profiles
# ==========================================

for cluster_id in sorted(
    final_enriched['cluster'].unique()
):

    cluster_data = final_enriched[
        final_enriched['cluster'] == cluster_id
    ]

    print(f"\n{'='*50}")
    print(f"CLUSTER {cluster_id}")
    print(f"{'='*50}")

    print("\nTop 5 CWEs:")
    print(
        cluster_data['cwe']
        .value_counts()
        .head(5)
    )

    print("\nTop 5 Vendors:")
    print(
        cluster_data['vendor']
        .value_counts()
        .head(5)
    )

    print("\nTop 5 Products:")
    print(
        cluster_data['product']
        .value_counts()
        .head(5)
    )