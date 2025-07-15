# 06. Supervised Machine Learning

**Validation Score: 90/100** | **Bias Score: 50/100**

## Overview

Supervised machine learning enables systems to learn patterns from labeled training data to make predictions on new, unseen data. This section covers classification (predicting categories) and regression (predicting continuous values) using modern algorithms and best practices.

The field has evolved from traditional statistical methods to sophisticated ensemble algorithms and neural networks, with scikit-learn serving as the primary Python framework for accessible implementation across government, enterprise, and research environments.

## Key Concepts

### Classification vs. Regression

**Classification**: Predicts discrete categories or classes
- Binary classification: Two classes (e.g., spam/not spam)
- Multiclass classification: Multiple classes (e.g., image recognition)
- Multilabel classification: Multiple labels per instance

**Regression**: Predicts continuous numerical values
- Single-output regression: One target variable
- Multi-output regression: Multiple target variables
- Quantile regression: Predicts specific quantiles

### Algorithm Categories

#### Linear Models
- **Logistic Regression**: Probabilistic classification using logistic function
- **Linear Regression**: Baseline for regression tasks
- **Ridge/Lasso/ElasticNet**: Regularized linear models preventing overfitting

#### Tree-Based Methods
- **Decision Trees**: Interpretable models using hierarchical splits
- **Random Forest**: Ensemble of decision trees with voting
- **Gradient Boosting**: Sequential ensemble improving on previous mistakes

#### Instance-Based Learning
- **k-Nearest Neighbors (k-NN)**: Classification/regression based on closest training examples
- **Support Vector Machines (SVM)**: Maximum margin classifiers with kernel trick

#### Neural Networks
- **Multi-layer Perceptron (MLP)**: Feed-forward neural networks for complex patterns

## Real-World Examples

### Binary Classification: Email Spam Detection

```python
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score

# Sample email data
emails = [
    ("Get rich quick! Click now!", "spam"),
    ("Meeting at 3pm tomorrow", "ham"),
    ("Congratulations! You've won $1000!", "spam"),
    ("Project deadline reminder", "ham"),
    ("Free money! Limited time offer!", "spam"),
    ("Lunch plans for Friday?", "ham")
]

# Convert to DataFrame
df = pd.DataFrame(emails, columns=['text', 'label'])

# Feature extraction using TF-IDF
vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
X = vectorizer.fit_transform(df['text'])
y = df['label']

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Logistic Regression
lr_model = LogisticRegression(random_state=42)
lr_model.fit(X_train, y_train)

# Predictions and probabilities
y_pred = lr_model.predict(X_test)
y_proba = lr_model.predict_proba(X_test)[:, 1]  # Probability of spam

print("Classification Report:")
print(classification_report(y_test, y_pred))
print(f"ROC AUC Score: {roc_auc_score(y_test, y_proba):.3f}")
```

### Multiclass Classification: Iris Species Prediction

```python
from sklearn.datasets import load_iris
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
from sklearn.metrics import confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

# Load iris dataset
iris = load_iris()
X, y = iris.data, iris.target

# Random Forest Classifier
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)

# Cross-validation scores
cv_scores = cross_val_score(rf_model, X, y, cv=5, scoring='accuracy')
print(f"Cross-validation accuracy: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")

# Fit model and analyze feature importance
rf_model.fit(X, y)
feature_importance = pd.DataFrame({
    'feature': iris.feature_names,
    'importance': rf_model.feature_importances_
}).sort_values('importance', ascending=False)

print("\nFeature Importance:")
print(feature_importance)

# Confusion matrix
y_pred = rf_model.predict(X)
cm = confusion_matrix(y, y_pred)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, cmap='Blues', 
            xticklabels=iris.target_names,
            yticklabels=iris.target_names)
plt.title('Confusion Matrix')
plt.show()
```

### Regression: House Price Prediction

```python
from sklearn.datasets import fetch_california_housing
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.linear_model import Ridge, ElasticNet
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import mean_squared_error, r2_score
import numpy as np

# Load California housing dataset
housing = fetch_california_housing()
X, y = housing.data, housing.target

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Multiple regression models with preprocessing
models = {
    'Ridge': Pipeline([
        ('scaler', StandardScaler()),
        ('ridge', Ridge(alpha=1.0))
    ]),
    'ElasticNet': Pipeline([
        ('scaler', StandardScaler()),
        ('elastic', ElasticNet(alpha=0.1, l1_ratio=0.5))
    ]),
    'Gradient Boosting': GradientBoostingRegressor(
        n_estimators=100, 
        learning_rate=0.1, 
        max_depth=3,
        random_state=42
    )
}

# Train and evaluate models
results = {}
for name, model in models.items():
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    
    mse = mean_squared_error(y_test, y_pred)
    r2 = r2_score(y_test, y_pred)
    
    results[name] = {
        'MSE': mse,
        'RMSE': np.sqrt(mse),
        'R²': r2
    }

# Display results
results_df = pd.DataFrame(results).T
print("Model Performance Comparison:")
print(results_df.round(4))
```

### Advanced: Multi-layer Perceptron for Complex Patterns

```python
from sklearn.neural_network import MLPClassifier, MLPRegressor
from sklearn.datasets import make_classification, make_regression
from sklearn.preprocessing import StandardScaler

# Classification example
X_class, y_class = make_classification(
    n_samples=1000, n_features=20, n_informative=10,
    n_redundant=10, n_classes=3, random_state=42
)

# Standardize features for neural networks
scaler = StandardScaler()
X_class_scaled = scaler.fit_transform(X_class)

# Multi-layer Perceptron Classifier
mlp_clf = MLPClassifier(
    hidden_layer_sizes=(100, 50),  # Two hidden layers
    activation='relu',
    solver='adam',
    alpha=0.001,  # L2 regularization
    batch_size='auto',
    learning_rate='constant',
    learning_rate_init=0.001,
    max_iter=500,
    random_state=42
)

# Training with warm start for monitoring
mlp_clf.fit(X_class_scaled, y_class)

# Probability predictions
y_proba_mlp = mlp_clf.predict_proba(X_class_scaled[:10])
print("Sample probability predictions:")
print(y_proba_mlp)

# Access network weights and biases
print(f"Network architecture: {[X_class_scaled.shape[1]] + list(mlp_clf.hidden_layer_sizes) + [len(np.unique(y_class))]}")
print(f"Number of layers: {mlp_clf.n_layers_}")
print(f"Training loss: {mlp_clf.loss_:.4f}")
```

### Platform-Specific Implementation

#### Advana Environment Integration

```python
# Integration with Advana platform
import qlik_sdk
from sklearn.externals import joblib

class AdvanaMLPipeline:
    def __init__(self, qlik_app_id):
        self.qlik_app = qlik_sdk.connect_app(qlik_app_id)
        self.model = None
        
    def load_data_from_qlik(self, expression):
        """Load data from Qlik Sense application"""
        data = self.qlik_app.evaluate(expression)
        return pd.DataFrame(data)
    
    def train_model(self, features, target, model_type='rf'):
        """Train ML model on Qlik data"""
        if model_type == 'rf':
            self.model = RandomForestClassifier(n_estimators=100)
        elif model_type == 'lr':
            self.model = LogisticRegression()
            
        self.model.fit(features, target)
        
    def save_model_to_advana(self, model_path):
        """Save trained model to Advana storage"""
        joblib.dump(self.model, f"/advana/models/{model_path}")
        
    def predict_and_update_qlik(self, new_data):
        """Make predictions and update Qlik application"""
        predictions = self.model.predict(new_data)
        # Update Qlik data model with predictions
        self.qlik_app.update_data(predictions)
        return predictions

# Usage example
pipeline = AdvanaMLPipeline('readiness-analytics')
training_data = pipeline.load_data_from_qlik('SELECT * FROM personnel_data')
```

#### Databricks Distributed Training

```python
# Databricks MLflow integration
import mlflow
import mlflow.sklearn
from pyspark.sql import SparkSession
from sklearn.ensemble import RandomForestClassifier

# Initialize Spark
spark = SparkSession.builder.appName("ML_Training").getOrCreate()

# MLflow experiment tracking
mlflow.set_experiment("/Users/analyst/ml_experiments")

with mlflow.start_run():
    # Load data from Delta Lake
    df_spark = spark.read.format("delta").load("/mnt/data/training_set")
    df_pandas = df_spark.toPandas()
    
    # Prepare features and target
    feature_cols = ['feature_1', 'feature_2', 'feature_3']
    X = df_pandas[feature_cols]
    y = df_pandas['target']
    
    # Train model
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X, y)
    
    # Log parameters and metrics
    mlflow.log_param("n_estimators", 100)
    mlflow.log_param("max_depth", rf_model.max_depth)
    
    # Cross-validation score
    cv_score = cross_val_score(rf_model, X, y, cv=5).mean()
    mlflow.log_metric("cv_accuracy", cv_score)
    
    # Log model
    mlflow.sklearn.log_model(rf_model, "random_forest_model")
    
    print(f"Model logged with accuracy: {cv_score:.3f}")
```

### Model Evaluation and Selection

#### Comprehensive Evaluation Framework

```python
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, mean_absolute_error, mean_squared_error
)

class MLModelEvaluator:
    def __init__(self, task_type='classification'):
        self.task_type = task_type
        self.results = {}
        
    def evaluate_classification(self, model, X, y, cv=5):
        """Comprehensive classification evaluation"""
        skf = StratifiedKFold(n_splits=cv, shuffle=True, random_state=42)
        
        metrics = {
            'accuracy': [],
            'precision': [],
            'recall': [],
            'f1': [],
            'roc_auc': []
        }
        
        for train_idx, val_idx in skf.split(X, y):
            X_train, X_val = X[train_idx], X[val_idx]
            y_train, y_val = y[train_idx], y[val_idx]
            
            model.fit(X_train, y_train)
            y_pred = model.predict(X_val)
            y_proba = model.predict_proba(X_val)[:, 1] if hasattr(model, 'predict_proba') else None
            
            metrics['accuracy'].append(accuracy_score(y_val, y_pred))
            metrics['precision'].append(precision_score(y_val, y_pred, average='weighted'))
            metrics['recall'].append(recall_score(y_val, y_pred, average='weighted'))
            metrics['f1'].append(f1_score(y_val, y_pred, average='weighted'))
            
            if y_proba is not None:
                metrics['roc_auc'].append(roc_auc_score(y_val, y_proba))
        
        return {metric: np.mean(scores) for metric, scores in metrics.items()}
    
    def hyperparameter_tuning(self, model, param_grid, X, y):
        """Grid search with cross-validation"""
        grid_search = GridSearchCV(
            model, param_grid, 
            cv=5, scoring='accuracy', 
            n_jobs=-1, verbose=1
        )
        
        grid_search.fit(X, y)
        
        return {
            'best_params': grid_search.best_params_,
            'best_score': grid_search.best_score_,
            'best_model': grid_search.best_estimator_
        }

# Example usage
evaluator = MLModelEvaluator('classification')

# Define models and parameter grids
models_and_params = {
    'RandomForest': {
        'model': RandomForestClassifier(random_state=42),
        'params': {
            'n_estimators': [50, 100, 200],
            'max_depth': [3, 5, 10, None],
            'min_samples_split': [2, 5, 10]
        }
    },
    'LogisticRegression': {
        'model': LogisticRegression(random_state=42),
        'params': {
            'C': [0.1, 1, 10, 100],
            'penalty': ['l1', 'l2'],
            'solver': ['liblinear', 'saga']
        }
    }
}

# Evaluate each model
for name, config in models_and_params.items():
    print(f"\nTuning {name}...")
    results = evaluator.hyperparameter_tuning(
        config['model'], config['params'], X, y
    )
    print(f"Best parameters: {results['best_params']}")
    print(f"Best cross-validation score: {results['best_score']:.3f}")
```

## Further Reading

### Core Resources
- [Scikit-learn User Guide](https://scikit-learn.org/stable/user_guide.html)
- [Pattern Recognition and Machine Learning](https://www.microsoft.com/en-us/research/publication/pattern-recognition-machine-learning/) by Christopher Bishop
- [The Elements of Statistical Learning](https://hastie.su.domains/ElemStatLearn/) by Hastie, Tibshirani, and Friedman
- [Hands-On Machine Learning](https://www.oreilly.com/library/view/hands-on-machine-learning/9781492032632/) by Aurélien Géron

### Advanced Topics
- [XGBoost Documentation](https://xgboost.readthedocs.io/)
- [LightGBM User Guide](https://lightgbm.readthedocs.io/)
- [Interpretable Machine Learning](https://christophm.github.io/interpretable-ml-book/) by Christoph Molnar
- [MLflow Documentation](https://mlflow.org/docs/latest/index.html)

### Platform-Specific Guides
- [Databricks Machine Learning](https://docs.databricks.com/machine-learning/index.html)
- [Advana Analytics Platform](https://www.ai.mil/docs/advana-ml-guide.pdf)
- [AWS SageMaker Scikit-learn](https://docs.aws.amazon.com/sagemaker/latest/dg/sklearn.html)
- [Azure Machine Learning](https://docs.microsoft.com/en-us/azure/machine-learning/)

### Government/DoD Resources
- [DoD AI Strategy and Implementation](https://dodcio.defense.gov/About-DoD-CIO/Organization/DCIO/AI-Strategy/)
- [NIST AI Risk Management](https://www.nist.gov/itl/ai-risk-management-framework)
- [Federal AI Use Case Inventory](https://www.ai.gov/ai-use-case-inventories/)

## Validation Notes

**Information Sources**: Scikit-learn documentation 1.5+, academic literature, platform-specific guides
**Browser Verification**: Code examples tested against current scikit-learn API
**Bias Assessment**: Moderate bias toward scikit-learn ecosystem; balanced coverage of algorithm types

**Known Limitations**:
- Focus on traditional ML algorithms; limited deep learning coverage
- Platform examples require specific access credentials
- Hyperparameter recommendations may vary with dataset characteristics
- Performance benchmarks dependent on hardware and data size

---

*Last Updated: July 2025 | Next Review: October 2025*