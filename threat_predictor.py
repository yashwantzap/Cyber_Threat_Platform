import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from imblearn.over_sampling import RandomOverSampler
import json
import os
import joblib
from datetime import date
import warnings
import numpy as np

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

# --- Configuration ---
DATA_DIR = "data"
MODEL_FILE = "threat_model.pkl"

def ensure_directory_exists(directory):
    """Ensures the specified directory exists."""
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Created directory: {directory}")

def load_latest_data(directory):
    """Loads the most recently created JSON file from the specified directory."""
    if not os.path.exists(directory):
        print(f"Directory {directory} not found.")
        return None
    
    files = [os.path.join(directory, f) for f in os.listdir(directory) if f.endswith('.json')]
    if not files:
        print("No JSON data files found.")
        print("Please run 'python data_collector.py' first to collect vulnerability data.")
        return None
    
    latest_file = max(files, key=os.path.getctime)
    print(f"Loading data from {latest_file}")
    
    try:
        with open(latest_file, 'r') as f:
            data = json.load(f)
        print(f"Successfully loaded {len(data)} vulnerability records")
        return data
    except Exception as e:
        print(f"Error loading data from {latest_file}: {e}")
        return None

def validate_data_structure(df):
    """Validates the structure and content of the loaded data."""
    print("\n📊 Data Validation Report:")
    print(f"  Total records: {len(df)}")
    print(f"  Total columns: {len(df.columns)}")
    
    # Check for missing values
    missing_data = df.isnull().sum()
    if missing_data.any():
        print("\n⚠️ Missing values found:")
        for col, count in missing_data[missing_data > 0].items():
            print(f"    {col}: {count} missing ({count/len(df)*100:.1f}%)")
    else:
        print("✅ No missing values found")
    
    # Data type information
    print("\n📋 Column Information:")
    for col in df.columns:
        dtype = df[col].dtype
        
        # Check if any values are lists and convert them to a string representation
        # This prevents the TypeError with nunique()
        # The .apply(lambda x: str(x) if isinstance(x, list) else x) is a safe way to handle this.
        if df[col].apply(lambda x: isinstance(x, list)).any():
            df[col] = df[col].apply(lambda x: ', '.join(map(str, x)) if isinstance(x, list) else x)

        unique_vals = df[col].nunique()
        print(f"    {col}: {dtype} ({unique_vals} unique values)")
    
    return True

def preprocess_and_train(data):
    """Preprocesses the data, trains a machine learning model, and evaluates it."""
    if not data:
        print("❌ No data provided for training.")
        return None
    
    print(f"\n🔄 Processing {len(data)} vulnerability records...")
    
    # Extract vulnerability information
    vulnerabilities_list = []
    for cve_id, vuln_data in data.items():
        if 'cve_info' in vuln_data:
            vulnerabilities_list.append(vuln_data['cve_info'])
    
    if not vulnerabilities_list:
        print("❌ No vulnerability data found in the loaded data.")
        return None
    
    df = pd.DataFrame(vulnerabilities_list)
    print(f"✅ Created DataFrame with {len(df)} rows and {len(df.columns)} columns")
    
    # Validate data structure
    validate_data_structure(df)
    
    # Check required columns
    required_columns = ['vulnerabilityName', 'shortDescription', 'vendorProject', 'product', 'requiredAction', 'dateAdded']
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        print(f"❌ Missing required columns: {missing_columns}")
        print("Available columns:", list(df.columns))
        return None
    
    print("✅ All required columns are present")
    
    # Date processing
    try:
        df['dateAdded'] = pd.to_datetime(df['dateAdded'], errors='coerce')
        df['days_since_added'] = (pd.to_datetime(date.today()) - df['dateAdded']).dt.days
        print(f"✅ Date processing complete. Date range: {df['dateAdded'].min()} to {df['dateAdded'].max()}")
    except Exception as e:
        print(f"❌ Error processing dates: {e}")
        return None

    # Feature Engineering - Risk Label Creation
    # Feature Engineering - Risk Label Creation
    def simplify_action(action):
        if pd.isna(action):
            return 'Low-Risk'
        
        action_lower = str(action).lower()
        
        # Medium-risk indicators
        medium_risk_keywords = [
            'apply updates', 'patch', 'remediation', 'vendor', 'mitigate',
            'security update', 'upgrade', 'fix available'
        ]
        if any(keyword in action_lower for keyword in medium_risk_keywords):
            return 'Medium-Risk'

        # High-risk indicators
        high_risk_keywords = [
            'due date', 'discontinue', 'remove', 'immediate action required', 
            'critical', 'emergency', 'exploit', 'zero-day', 'active exploitation'
        ]
        if any(keyword in action_lower for keyword in high_risk_keywords):
            return 'High-Risk'
        
        return 'Low-Risk'
    
    df['risk_label'] = df['requiredAction'].apply(simplify_action)
    
    print("\n📊 Risk Label Distribution:")
    risk_distribution = df['risk_label'].value_counts()
    for risk_level, count in risk_distribution.items():
        percentage = (count / len(df)) * 100
        print(f"    {risk_level}: {count} ({percentage:.1f}%)")
    
    # Ensure we have enough samples for each class
    class_counts = df['risk_label'].value_counts()
    min_class_size = 2  # Reduced minimum for small datasets
    valid_classes = class_counts[class_counts >= min_class_size].index
    
    print(f"\n🔍 Classes with sufficient samples (>= {min_class_size}):")
    for cls in valid_classes:
        print(f"    {cls}: {class_counts[cls]} samples")
    
    df = df[df['risk_label'].isin(valid_classes)]

    if len(df['risk_label'].unique()) < 2:
        print("❌ Not enough classes for classification after filtering.")
        print("Need at least 2 classes with minimum sample sizes.")
        return None

    print(f"✅ After filtering: {len(df)} samples with {len(df['risk_label'].unique())} classes")

    # Prepare features
    features = ['vulnerabilityName', 'shortDescription', 'vendorProject', 'product', 'days_since_added']
    X = df[features].copy()
    y = df['risk_label']

    # Handle missing values
    print("\n🔧 Handling missing values...")
    X['vulnerabilityName'] = X['vulnerabilityName'].fillna('Unknown')
    X['shortDescription'] = X['shortDescription'].fillna('No description')
    X['vendorProject'] = X['vendorProject'].fillna('Unknown')
    X['product'] = X['product'].fillna('Unknown')
    X['days_since_added'] = X['days_since_added'].fillna(0)
    
    print("✅ Missing values handled")

    # Create preprocessing pipeline
    text_features = ['vulnerabilityName', 'shortDescription']
    categorical_features = ['vendorProject', 'product']
    numerical_features = ['days_since_added']

    print("\n🏗️ Building preprocessing pipeline...")
    preprocessor = ColumnTransformer(
        transformers=[
            ('text_name', TfidfVectorizer(stop_words='english', max_features=500, ngram_range=(1,2)), 'vulnerabilityName'),
            ('text_desc', TfidfVectorizer(stop_words='english', max_features=500, ngram_range=(1,2)), 'shortDescription'),
            ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), categorical_features),
            ('num', 'passthrough', numerical_features)
        ],
        remainder='drop'
    )

    # Process features
    try:
        print("🔄 Processing features...")
        X_processed = preprocessor.fit_transform(X)
        print(f"✅ Feature matrix shape: {X_processed.shape}")
        print(f"    Features per sample: {X_processed.shape[1]}")
    except Exception as e:
        print(f"❌ Error during preprocessing: {e}")
        return None

    # Handle class imbalance if we have enough data
    X_resampled, y_resampled = X_processed, y
    if len(df) > 10:
        try:
            print("\n⚖️ Handling class imbalance...")
            sampler = RandomOverSampler(random_state=42)
            X_resampled, y_resampled = sampler.fit_resample(X_processed, y)
            print(f"✅ After oversampling: {X_resampled.shape[0]} samples")
            
            # Show new distribution
            unique, counts = np.unique(y_resampled, return_counts=True)
            print("    New class distribution:")
            for cls, count in zip(unique, counts):
                print(f"        {cls}: {count} samples")
                
        except Exception as e:
            print(f"⚠️ Oversampling failed, using original data: {e}")
            X_resampled, y_resampled = X_processed, y

    # Train-test split
    print("\n📊 Splitting data for training and testing...")
    if len(X_resampled) > 4:  # Need at least 4 samples for split
        try:
            test_size = max(0.1, min(0.3, 0.2))  # Adaptive test size
            X_train, X_test, y_train, y_test = train_test_split(
                X_resampled, y_resampled, 
                test_size=test_size, 
                random_state=42, 
                stratify=y_resampled if len(np.unique(y_resampled)) > 1 else None
            )
            print(f"✅ Train set: {X_train.shape[0]} samples")
            print(f"✅ Test set: {X_test.shape[0]} samples")
        except Exception as e:
            print(f"⚠️ Stratified split failed, using simple split: {e}")
            split_idx = int(0.8 * len(X_resampled))
            X_train, X_test = X_resampled[:split_idx], X_resampled[split_idx:]
            y_train, y_test = y_resampled[:split_idx], y_resampled[split_idx:]
            print(f"✅ Train set: {len(X_train)} samples")
            print(f"✅ Test set: {len(X_test)} samples")
    else:
        # Not enough data for proper split, use all data for training
        X_train, X_test = X_resampled, X_resampled
        y_train, y_test = y_resampled, y_resampled
        print("⚠️ Warning: Using all data for both training and testing due to small dataset size.")

    # Train the model
    print("\n🤖 Training the machine learning model...")
    try:
        # Use adaptive hyperparameters based on dataset size
        n_estimators = min(100, max(10, len(X_train) // 2))
        max_depth = min(20, max(3, len(X_train) // 10))
        
        classifier = RandomForestClassifier(
            n_estimators=n_estimators,
            random_state=42,
            max_depth=max_depth,
            min_samples_split=max(2, len(X_train) // 50),
            min_samples_leaf=max(1, len(X_train) // 100)
        )
        
        print(f"  Model parameters:")
        print(f"    n_estimators: {n_estimators}")
        print(f"    max_depth: {max_depth}")
        
        classifier.fit(X_train, y_train)
        print("✅ Model training complete!")
    except Exception as e:
        print(f"❌ Model training failed: {e}")
        return None

    # Evaluate the model
    evaluation_success = False
    if len(X_test) > 0:
        print("\n📈 Evaluating the model...")
        try:
            y_pred = classifier.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            print(f"✅ Model Accuracy: {accuracy:.2%}")
            
            # Detailed classification report
            print("\n📋 Classification Report:")
            print("="*50)
            report = classification_report(y_test, y_pred, zero_division=0)
            print(report)
            
            # Confusion Matrix
            if len(np.unique(y_test)) > 1:
                print("\n🔍 Confusion Matrix:")
                cm = confusion_matrix(y_test, y_pred)
                labels = sorted(np.unique(y_test))
                
                print("Predicted →")
                print("Actual ↓   ", end="")
                for label in labels:
                    print(f"{label:>12}", end="")
                print()
                
                for i, true_label in enumerate(labels):
                    print(f"{true_label:>10} ", end="")
                    for j in range(len(labels)):
                        print(f"{cm[i,j]:>12}", end="")
                    print()
            
            # Feature importance (top 10)
            if hasattr(classifier, 'feature_importances_'):
                print(f"\n🎯 Top 10 Most Important Features:")
                feature_names = []
                
                # Get feature names from the preprocessor
                try:
                    # This is approximate since we have transformed features
                    importance_indices = np.argsort(classifier.feature_importances_)[-10:][::-1]
                    for i, idx in enumerate(importance_indices):
                        importance = classifier.feature_importances_[idx]
                        print(f"    {i+1:2d}. Feature {idx:3d}: {importance:.4f}")
                except:
                    print("    Feature names not available in transformed space")
            
            evaluation_success = True
            
        except Exception as e:
            print(f"⚠️ Model evaluation failed: {e}")

    # Create and save the final pipeline
    try:
        print(f"\n💾 Saving the trained model...")
        final_pipeline = Pipeline(steps=[
            ('preprocessor', preprocessor),
            ('classifier', classifier)
        ])
        
        # Save the model
        joblib.dump(final_pipeline, MODEL_FILE)
        print(f"✅ Model saved successfully to '{MODEL_FILE}'")
        
        # Save model metadata
        model_info = {
            'training_date': date.today().isoformat(),
            'total_samples': len(df),
            'features_used': features,
            'classes': list(df['risk_label'].unique()),
            'model_type': 'RandomForestClassifier',
            'accuracy': accuracy if evaluation_success else 'Not evaluated',
            'data_source': f"Latest file from {DATA_DIR}"
        }
        
        info_file = MODEL_FILE.replace('.pkl', '_info.json')
        with open(info_file, 'w') as f:
            json.dump(model_info, f, indent=2, default=str)
        print(f"✅ Model information saved to '{info_file}'")
        
        return final_pipeline
        
    except Exception as e:
        print(f"❌ Failed to save model: {e}")
        return None

def display_training_summary(model):
    """Displays a summary of the training process."""
    if model is None:
        print("\n❌ Training Summary: Model training failed")
        return
    
    print("\n" + "="*60)
    print("🎉 TRAINING COMPLETED SUCCESSFULLY!")
    print("="*60)
    print("✅ Model trained and saved successfully")

def main():
    """Main function to run the training process."""
    print("🚀 Cybersecurity Threat Prediction Model Training")
    print("="*60)
    
    # Ensure data directory exists
    ensure_directory_exists(DATA_DIR)
    
    # Load the latest vulnerability data
    print("📁 Loading vulnerability data...")
    raw_data = load_latest_data(DATA_DIR)
    
    if raw_data:
        print(f"✅ Data loaded successfully")
        
        # Train the model
        trained_model = preprocess_and_train(raw_data)
        
        # Display training summary
        display_training_summary(trained_model)
        
        if trained_model:
            print(f"\n🎯 Model is ready for use!")
            return True
        else:
            print(f"\n❌ Training failed. Please check the error messages above.")
            return False
    else:
        print("❌ No data available for training.")
        return False

if __name__ == "__main__":
    success = main()
    if success:
        print("\n👍 Ready to proceed with threat mitigation!")
    else:
        print("\n👎 Please resolve the issues above and try again.")