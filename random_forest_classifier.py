import json
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay

import matplotlib.pyplot as plt

# Load your raw JSON data
with open("data/20sec/random_forest_data.json") as f:
    raw_data = json.load(f)

# Convert to DataFrame
df = pd.DataFrame({
    "features": [item["features"] for item in raw_data],
    "label": [item["label"] for item in raw_data]
})

# Expand features into individual columns
features_df = pd.DataFrame(df["features"].to_list())
features_df.columns = [
    "outgoing_len_mean", "outgoing_len_median", "outgoing_len_std",
    "incoming_len_mean", "incoming_len_median", "incoming_len_std",
    "iat_mean", "iat_median", "iat_std", "iat_tail_mean",
    "incoming_pkt_count", "outgoing_pkt_count"
]

X = features_df
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.3, random_state=42)

clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)


print("Classification Report:")
print(classification_report(y_test, y_pred))

print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# plot confusion matrix

cm = confusion_matrix(y_test, y_pred)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["YouTube", "Zoom", "Twitch"])
disp.plot(cmap=plt.cm.Blues)
plt.title("Confusion Matrix - Random Forest")
plt.savefig("confusion_matrix_random_forest.png")  # <-- Save it!

plt.show()



importances = clf.feature_importances_
for name, importance in zip(X.columns, importances):
    print(f"{name}: {importance:.4f}")
