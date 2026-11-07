import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score, accuracy_score
import joblib
from feature_extractor import FEATURE_NAMES

DATASET_PATH = os.path.join(os.path.dirname(__file__), 'dataset.csv')
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.joblib')

def main():
    print(f"Loading dataset from: {DATASET_PATH} ...")
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(f"dataset.csv not found at {DATASET_PATH}")
        
    df = pd.read_csv(DATASET_PATH)
    print(f"Dataset loaded: {len(df)} total samples")
    print(f"  - Legitimate (0): {sum(df['label'] == 0)}")
    print(f"  - Phishing (1):   {sum(df['label'] == 1)}")
    
    # Feature matrix X and labels y
    X = df[FEATURE_NAMES].values
    y = df['label'].values
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    
    print("\nTraining Random Forest Classifier...")
    rf = RandomForestClassifier(
        n_estimators=120,
        max_depth=12,
        min_samples_split=2,
        class_weight='balanced',
        random_state=42
    )
    rf.fit(X_train, y_train)
    
    y_pred = rf.predict(X_test)
    y_prob = rf.predict_proba(X_test)[:, 1]
    
    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)
    
    print(f"\n================ Model Performance ================")
    print(f"Accuracy: {acc * 100:.2f}%")
    print(f"ROC-AUC Score: {auc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    # Save model
    model_package = {
        'model': rf,
        'feature_names': FEATURE_NAMES,
        'metrics': {
            'accuracy': float(acc),
            'auc': float(auc)
        }
    }
    
    joblib.dump(model_package, MODEL_PATH)
    print(f"\nTrained model successfully saved to: {MODEL_PATH}")

if __name__ == '__main__':
    main()
