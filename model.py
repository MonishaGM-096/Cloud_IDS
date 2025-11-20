import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import joblib  # To load your trained model

# Load the dataset
df = pd.read_csv("dataset/KDDTrain+.TXT", header=None)

# Define feature names (based on NSL-KDD dataset)
feature_names = [
    "Duration", "Protocol Type", "Service", "Flag", "Src Bytes", "Dst Bytes",
    "Land", "Wrong Fragment", "Urgent", "Hot", "Num Failed Logins",
    "Logged In", "Num Compromised", "Root Shell", "Su Attempted",
    "Num Root", "Num File Creations", "Num Shells", "Num Access Files",
    "Num Outbound Cmds", "Is Hot Login", "Is Guest Login",
    "Count", "Srv Count", "Serror Rate", "Srv Serror Rate",
    "Rerror Rate", "Srv Rerror Rate", "Same Srv Rate",
    "Diff Srv Rate", "Srv Diff Host Rate", "Dst Host Count",
    "Dst Host Srv Count", "Dst Host Same Srv Rate",
    "Dst Host Diff Srv Rate", "Dst Host Same Src Port Rate",
    "Dst Host Srv Diff Host Rate", "Dst Host Serror Rate",
    "Dst Host Srv Serror Rate", "Dst Host Rerror Rate",
    "Dst Host Srv Rerror Rate"
]

# Load trained Random Forest model
rf_model = joblib.load("random_forest_nsl_kdd.pkl")

# Get feature importance
importances = rf_model.feature_importances_

# Print lengths for debugging
print(f"Length of feature_names: {len(feature_names)}")
print(f"Length of importances: {len(importances)}")

# Ensure both have the same length
if len(feature_names) == len(importances):
    # Create DataFrame only if lengths match
    feature_importance_df = pd.DataFrame({"Feature": feature_names, "Importance": importances})
    feature_importance_df = feature_importance_df.sort_values(by="Importance", ascending=False)

    # Display top 15 features
    top_features = feature_importance_df.head(15)
    print("Top 15 Important Features:")
    print(top_features)

    # Plot feature importance
    import matplotlib.pyplot as plt
    import seaborn as sns

    plt.figure(figsize=(12, 6))
    sns.barplot(x=top_features["Importance"], y=top_features["Feature"], palette="viridis")
    plt.xlabel("Feature Importance Score")
    plt.ylabel("Features")
    plt.title("Top 15 Important Features in NSL-KDD Dataset")
    plt.show()
else:
    print("Error: Mismatch in feature_names and importances lengths!")

# Get feature importance from the model
importances = rf_model.feature_importances_

# Check how many features were actually used
print(f"Number of features used by the model: {len(importances)}")

# Get the feature names used by the model
used_feature_names = feature_names[:len(importances)]  # Select only the first 22 features

# Create a DataFrame with correct feature names
feature_importance_df = pd.DataFrame({"Feature": used_feature_names, "Importance": importances})
feature_importance_df = feature_importance_df.sort_values(by="Importance", ascending=False)

# Display top 15 important features
top_features = feature_importance_df.head(15)
print("Top 15 Important Features Used by Model:")
print(top_features)
