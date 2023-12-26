import pandas as pd
import shap
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor

# 1. Load and Preprocess the Data
data = pd.read_csv("/Users/fatimasohail/Downloads/pseudonym_log.csv")

# 2. Add the "Has Seen Before" Column for Pseudonyms
data["has_seen_before"] = 0

# 3. Split the Data
features = ["Pseudonym", "has_seen_before", "PosX", "PosY", "VelocityY"]
X = data[features]
y = data["VelocityX"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

X_train["Pseudonym"] = X_train["Pseudonym"].apply(lambda x: int(x[:16], 16))
X_test["Pseudonym"] = X_test["Pseudonym"].apply(lambda x: int(x[:16], 16))

model_pseudo = RandomForestRegressor()
model_pseudo.fit(X_train, y_train)

accuracy_pseudo = model_pseudo.score(X_test, y_test)
print(f"Accuracy using Pseudonyms: {accuracy_pseudo}")

explainer = shap.TreeExplainer(model_pseudo)
shap_values = explainer.shap_values(X_test)

shap.summary_plot(shap_values, X_test)
