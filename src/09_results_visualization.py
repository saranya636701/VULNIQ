import pandas as pd
import matplotlib.pyplot as plt


# ==========================================
# Load Final Enriched Dataset
# ==========================================

data = pd.read_csv(
    "../data/processed/cve_kmeans_k4_enriched.csv"
)

print("Dataset loaded:", data.shape)


# ==========================================
# 1. Cluster Distribution
# ==========================================

cluster_counts = data['cluster'].value_counts().sort_index()

cluster_percentages = (
    cluster_counts / len(data) * 100
).round(2)

print("\nCluster Distribution:")

for cluster in cluster_counts.index:
    print(
        f"Cluster {cluster}: "
        f"{cluster_counts[cluster]} CVEs "
        f"({cluster_percentages[cluster]}%)"
    )


# Plot Cluster Distribution

plt.figure(figsize=(8, 5))

bars = plt.bar(
    cluster_counts.index.astype(str),
    cluster_counts.values
)

plt.title(
    "Distribution of Vulnerabilities Across K-Means Clusters"
)
plt.xlabel("Cluster")
plt.ylabel("Number of CVEs")

# Add percentage above each bar
for bar, percentage in zip(
    bars,
    cluster_percentages
):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        bar.get_height(),
        f"{percentage}%",
        ha="center",
        va="bottom"
    )

plt.tight_layout()
plt.show()


# ==========================================
# 2. Numerical Cluster Profile
# ==========================================

numeric_features = [
    'base_score',
    'exploitability_score',
    'impact_score',
    'epss_score',
    'epss_perc',
    'vulnerability_age_days'
]

cluster_profile = (
    data
    .groupby('cluster')[numeric_features]
    .mean()
    .round(2)
)

print("\nNumerical Cluster Profile:")
print(cluster_profile)


# Rename for cleaner chart

cluster_profile.columns = [
    'Base Score',
    'Exploitability',
    'Impact',
    'EPSS',
    'EPSS Percentile',
    'Vulnerability Age'
]


# Plot Numerical Profile

cluster_profile.T.plot(
    kind='bar',
    figsize=(11, 6)
)

plt.axhline(0, linewidth=1)

plt.title(
    "Numerical Characteristics of Vulnerability Clusters"
)
plt.xlabel("Vulnerability Feature")
plt.ylabel("Standardized Mean")

plt.xticks(
    rotation=30,
    ha='right'
)

plt.legend(title="Cluster")

plt.tight_layout()
plt.show()


# ==========================================
# 3. CISA KEV Distribution Across Clusters
# ==========================================

kev_counts = (
    data[data['cisa_kev'] == 1]
    ['cluster']
    .value_counts()
    .sort_index()
)

total_kev = kev_counts.sum()

kev_share = (
    kev_counts / total_kev * 100
).round(2)


print("\nCISA KEV Distribution:")

for cluster in kev_counts.index:
    print(
        f"Cluster {cluster}: "
        f"{kev_counts[cluster]} KEVs "
        f"({kev_share[cluster]}% of all KEVs)"
    )


# Plot KEV Distribution

plt.figure(figsize=(8, 5))

bars = plt.bar(
    kev_counts.index.astype(str),
    kev_counts.values
)

plt.title(
    "Distribution of CISA Known Exploited Vulnerabilities"
)
plt.xlabel("Cluster")
plt.ylabel("Number of CISA KEVs")

for bar, percentage in zip(
    bars,
    kev_share
):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        bar.get_height(),
        f"{percentage}%",
        ha="center",
        va="bottom"
    )

plt.tight_layout()
plt.show()


# ==========================================
# 4. Top 3 CWE by Cluster
# ==========================================

for cluster_id in sorted(
    data['cluster'].unique()
):

    cluster_data = data[
        data['cluster'] == cluster_id
    ]

    # Remove generic CWE categories
    valid_cwe = cluster_data[
        ~cluster_data['cwe'].isin([
            'NVD-CWE-Other',
            'NVD-CWE-noinfo'
        ])
    ]

    top_cwe = (
        valid_cwe['cwe']
        .value_counts()
        .head(3)
    )

    print(
        f"\nTop 3 CWEs - Cluster {cluster_id}:"
    )
    print(top_cwe)

    plt.figure(figsize=(7, 4))

    bars = plt.bar(
        top_cwe.index,
        top_cwe.values
    )

    plt.title(
        f"Top CWE Patterns - Cluster {cluster_id}"
    )
    plt.xlabel("CWE")
    plt.ylabel("Number of CVEs")

    for bar in bars:
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{int(bar.get_height())}",
            ha="center",
            va="bottom"
        )

    plt.tight_layout()
    plt.show()


# ==========================================
# 5. Top 5 Vendors by Cluster
# ==========================================

for cluster_id in sorted(
    data['cluster'].unique()
):

    cluster_data = data[
        data['cluster'] == cluster_id
    ]

    top_vendors = (
        cluster_data['vendor']
        .dropna()
        .value_counts()
        .head(5)
    )

    print(
        f"\nTop 5 Vendors - Cluster {cluster_id}:"
    )
    print(top_vendors)

    plt.figure(figsize=(7, 4))

    bars = plt.bar(
        top_vendors.index,
        top_vendors.values
    )

    plt.title(
        f"Top Vendors - Cluster {cluster_id}"
    )
    plt.xlabel("Vendor")
    plt.ylabel("Number of CVEs")

    plt.xticks(
        rotation=30,
        ha='right'
    )

    for bar in bars:
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{int(bar.get_height())}",
            ha="center",
            va="bottom"
        )

    plt.tight_layout()
    plt.show()