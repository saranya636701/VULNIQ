import pandas as pd

# Step1: Load the preprocessed dataset

dataset1 = pd.read_csv(
    "../data/processed/cve_cisa_epss_preprocessed.csv"
)

print("\nDataset loaded successfully")
print(dataset1.head())

print("\nData types:")
print(dataset1.dtypes)


# Step2: Convert the published_date column to datetime format.
# When you save a DataFrame to CSV, the published_date column
# is written back as text.

dataset1["published_date"] = pd.to_datetime(
    dataset1["published_date"],
    format="mixed"
)

print("\nData type of published_date after conversion:")
print(dataset1["published_date"].dtype)


# Step3: Create Vulnerability Age feature

reference_date = pd.Timestamp("2026-08-01")

dataset1["vulnerability_age_days"] = (
    reference_date - dataset1["published_date"]
).dt.days

print("\nVulnerability Age feature created successfully")

print(
    dataset1[
        [
            "cve_id",
            "published_date",
            "vulnerability_age_days"
        ]
    ].head()
)


# Step4: Validate vulnerability age feature

print("\nVulnerability Age Statistics:")
print(dataset1["vulnerability_age_days"].describe())

print("\nNegative vulnerability ages:")
print(
    (dataset1["vulnerability_age_days"] < 0).sum()
)


# Step5: Save feature engineered dataset

dataset1.to_csv(
    "../data/processed/cve_feature_engineered.csv",
    index=False
)

print("\nFeature engineered dataset saved successfully.")