import pandas as pd

# Load feature engineered dataset

dataset1 = pd.read_csv(
    "../data/processed/cve_feature_engineered.csv"
)

print("\nDataset loaded successfully")

print(dataset1.shape)

print("\nUnique values per column:")

print(dataset1.nunique().sort_values())


# Check variables with low variance

numeric_features = [
    'base_score',
    'exploitability_score',
    'impact_score',
    'epss_score',
    'epss_perc',
    'vulnerability_age_days'
]

print("\nVariance of numerical features:")
print(dataset1[numeric_features].var().sort_values())


# Check Correlation between features

correlation_matrix = dataset1[numeric_features].corr()

print("\nCorrelation Matrix:")
print(correlation_matrix.round(3))


# ============================
# Final Feature Selection
# ============================

selected_features = [
    'base_score',
    'exploitability_score',
    'impact_score',
    'epss_score',
    'epss_perc',
    'cisa_kev',
    'attack_vector',
    'attack_complexity',
    'privileges_required',
    'user_interaction',
    'scope',
    'confidentiality_impact',
    'integrity_impact',
    'availability_impact',
    'vulnerability_age_days'
]

# Create final dataset for clustering

selected_dataset = dataset1[selected_features]

print("\nSelected Features:")
print(selected_dataset.columns.tolist())

print("\nShape of selected dataset:")
print(selected_dataset.shape)


# Save selected features dataset

selected_dataset.to_csv(
    "../data/processed/cve_selected_features.csv",
    index=False
)

print(
    "\nSelected feature dataset saved successfully "
    "as 'cve_selected_features.csv'"
)