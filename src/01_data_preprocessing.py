# 1. LOAD THE DATASETS

import pandas as pd

dataset1 = pd.read_csv("../data/raw/cve_cisa_epss_enriched_dataset.csv")
dataset2 = pd.read_csv("../data/raw/cve_corpus.csv")


# 2. UNDERSTAND THE DATASET1

# Display first 5 rows
print("\nFirst 5 rows of dataset1:")
print(dataset1.head())

# Check dimensions
print("\nDimensions of dataset1:")
print(dataset1.shape)

# View column names
print("\nColumn names of dataset1:")
print(dataset1.columns)

# Check data types and missing values
print("\nData types and missing values in dataset1:")
print(dataset1.info())

# Summary statistics
print("\nSummary statistics for dataset1:")
print(dataset1.describe(include='all'))

# Duplicate CVEs
print("\nNumber of duplicate CVEs in dataset1:")
print(dataset1.duplicated(subset='cve_id').sum())

# Why are these values missing - lets investigate privileges_required column?
print("\nRows with missing 'privileges_required' values:")
print(dataset1[dataset1['privileges_required'].isnull()].head())

# Distribution of severity for missing rows
print("\nDistribution of severity for missing rows:")
print(
    dataset1[
        dataset1['privileges_required'].isnull()
    ]['base_severity'].value_counts()
)

# Convert published_date to datetime
print("\nConverting 'published_date' to datetime format...")

dataset1['published_date'] = pd.to_datetime(
    dataset1['published_date'],
    format='mixed'
)

print("\nData type of 'published_date' after conversion:")
print(dataset1['published_date'].dtype)


# Missing values summary

print("\nMissing values in dataset1:")

missing_values = pd.DataFrame({
    'Missing Count': dataset1.isnull().sum(),
    'Missing Percentage':
        (dataset1.isnull().sum() / len(dataset1)) * 100
})

print(
    missing_values[
        missing_values['Missing Count'] > 0
    ].sort_values(
        by='Missing Count',
        ascending=False
    )
)


# Check if the three CVSS v3 columns are always missing together

missing_pattern = dataset1[
    ['privileges_required', 'user_interaction', 'scope']
].isnull()

print("\nMissing value pattern:")
print(missing_pattern.value_counts())


# Fill CVSS v3-specific missing values

cvss_v3_columns = [
    'privileges_required',
    'user_interaction',
    'scope'
]

for col in cvss_v3_columns:
    dataset1[col] = dataset1[col].fillna('NOT_DEFINED')

print("\nMissing values in CVSS v3 columns after filling:")
print(dataset1[cvss_v3_columns].isnull().sum())


# Fill missing values in EPSS columns with the median

dataset1['epss_score'] = dataset1['epss_score'].fillna(
    dataset1['epss_score'].median()
)

dataset1['epss_perc'] = dataset1['epss_perc'].fillna(
    dataset1['epss_perc'].median()
)

print("\nMissing values in EPSS columns after filling:")
print(dataset1[['epss_score', 'epss_perc']].isnull().sum())


# Check unique values in categorical columns

categorical_columns = [
    'base_severity',
    'attack_vector',
    'attack_complexity',
    'privileges_required',
    'user_interaction',
    'scope',
    'confidentiality_impact',
    'integrity_impact',
    'availability_impact'
]

print("\nUnique values in categorical columns:")

for col in categorical_columns:

    print(f"\n{'='*50}")
    print(f"{col}")
    print(f"{'='*50}")

    print(sorted(dataset1[col].unique()))


# Check numeric columns

print("\nNumeric Feature Summary:")

numeric_columns = [
    'base_score',
    'exploitability_score',
    'impact_score',
    'epss_score',
    'epss_perc'
]

print("\nSummary statistics for numeric columns:")
print(dataset1[numeric_columns].describe())


# Check for potential outliers using boxplot statistics

print("\nChecking for potential outliers using boxplot statistics...")

for col in numeric_columns:

    Q1 = dataset1[col].quantile(0.25)
    Q3 = dataset1[col].quantile(0.75)

    IQR = Q3 - Q1

    lower = Q1 - 1.5 * IQR
    upper = Q3 + 1.5 * IQR

    outliers = dataset1[
        (dataset1[col] < lower) |
        (dataset1[col] > upper)
    ].shape[0]

    print(f"{col}: {outliers} potential outliers")


# Save the preprocessed dataset to a new CSV file

dataset1.to_csv(
    "../data/processed/cve_cisa_epss_preprocessed.csv",
    index=False
)

print("\nPreprocessed dataset saved successfully.")