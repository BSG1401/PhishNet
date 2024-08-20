import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib

dataset_path = os.path.join('static', 'URL dataset.csv')

# Load the dataset
dataset = pd.read_csv(dataset_path)

# Update the label column to numerical format
# Make absolutely sure that 'phishing' is the correct label and the case is right
dataset['type'] = dataset['type'].apply(lambda x: 1 if x == 'phishing' else 0)

# Feature extraction function
def extract_features(url):
    features = {
        'url_length': len(url),
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_slashes': url.count('/'),
        'num_at': url.count('@'),
        'num_digits': sum(c.isdigit() for c in url),
        'num_letters': sum(c.isalpha() for c in url),
        'num_params': url.count('?'),
        'num_equals': url.count('='),
        'num_hashes': url.count('#'),
        'num_underscores': url.count('_'),
        'num_tildes': url.count('~'),
        'num_ampersands': url.count('&'),
        'num_percent': url.count('%'),
    }
    return features

# Apply feature extraction to the dataset
features = dataset['url'].apply(extract_features)
features_df = pd.DataFrame(features.tolist())

# Combine features with original dataset
X = features_df
y = dataset['type']

# Split into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Check class distribution BEFORE training
print("Class distribution in training set:", y_train.value_counts())
print("Class distribution in testing set:", y_test.value_counts())

# Handle class imbalance if necessary (uncomment and adjust if needed)
# from imblearn.over_sampling import SMOTE
# smote = SMOTE(random_state=42)
# X_train, y_train = smote.fit_resample(X_train, y_train)

# Train a Gradient Boosting Classifier
model = GradientBoostingClassifier(n_estimators=100, max_depth=20, random_state=42)
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
classification_rep = classification_report(y_test, y_pred)

print(f"Model Accuracy: {accuracy * 100:.2f}%")
print("Classification Report:\n", classification_rep)

# Save the trained model to a .pkl file
joblib.dump(model, 'phishing_model.pkl')
