import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os

# 1. Load the data
print("[*] Loading dataset from data/data1.csv...")
df = pd.read_csv('data/data1.csv')

# 2. Data Cleaning
# We must drop 'Name' because it is a string (hash), and ML only speaks numbers.
# We drop 'Malware' because that is the answer we want the model to find.
X = df.drop(['Name', 'Malware'], axis=1)
y = df['Malware']

# 3. Train/Test Split (80% for training, 20% for testing the accuracy)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. Initialize the Brain
print("[*] Training Random Forest with 100 trees...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)

# 5. The Training Process
model.fit(X_train, y_train)

# 6. Evaluation
predictions = model.predict(X_test)
acc = accuracy_score(y_test, predictions)

print("\n===============================")
print(f"   MODEL ACCURACY: {acc * 100:.2f}%")
print("===============================\n")
print(classification_report(y_test, predictions))

# 7. Save the Brain
if not os.path.exists('models'):
    os.makedirs('models')

joblib.dump(model, 'models/malware_brain.pkl')
print("[+] Model saved to models/malware_brain.pkl")

# Save the column names so our extractor knows the order later
joblib.dump(X.columns.tolist(), 'models/features.pkl')
print("[+] Feature list saved to models/features.pkl")