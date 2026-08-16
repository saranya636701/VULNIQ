import pandas as pd
from sklearn.preprocessing import StandardScaler


# ==========================================
# 1. Load selected features dataset
# ==========================================

dataset = pd.read_csv(
    "../data/processed/cve_selected_features.csv"
)

print("Dataset loaded successfully")
print(dataset.head())

print("\nData Types:")
print(dataset.dtypes)


# ==========================================
# 2. Convert boolean feature to integer
# ==========================================

dataset['cisa_kev'] = dataset['cisa_kev'].astype(int)

print("\nBoolean feature converted:")
print(dataset['cisa_kev'].value_counts())

print("\nData type:")
print(dataset['cisa_kev'].dtype)


# ==========================================
# 3. One-Hot Encoding
# ==========================================

categorical_features = [
    'attack_vector',
    'attack_complexity',
    'privileges_required',
    'user_interaction',
    'scope',
    'confidentiality_impact',
    'integrity_impact',
    'availability_impact'
]

dataset_encoded = pd.get_dummies(
    dataset,
    columns=categorical_features,
    drop_first=False,
    dtype=int
)

print("\nDataset after One-Hot Encoding:")
print(dataset_encoded.head())

print("\nShape after encoding:")
print(dataset_encoded.shape)

print("\nEncoded column names:")
print(dataset_encoded.columns.tolist())


# ==========================================
# 4. Standard Scaling
# ==========================================

numerical_features = [
    'base_score',
    'exploitability_score',
    'impact_score',
    'epss_score',
    'epss_perc',
    'vulnerability_age_days'
]

scaler = StandardScaler()

dataset_encoded[numerical_features] = scaler.fit_transform(
    dataset_encoded[numerical_features]
)

print("\nScaling completed successfully.")

print("\nFirst 5 rows after scaling:")
print(dataset_encoded.head())

print("\nMean of scaled numerical features:")
print(dataset_encoded[numerical_features].mean())

print("\nStandard deviation of scaled numerical features:")
print(dataset_encoded[numerical_features].std())


# ==========================================
# 5. Save encoded and scaled dataset
# ==========================================

dataset_encoded.to_csv(
    "../data/processed/cve_encoded_scaled.csv",
    index=False
)

print("\nEncoded and scaled dataset saved successfully.")

print("\nFinal dataset shape:")
print(dataset_encoded.shape)