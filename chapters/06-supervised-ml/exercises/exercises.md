# Chapter 06 Exercises: Supervised Machine Learning

These exercises use the synthetic data generators from the code examples directory. Where indicated, extend them to work on a real Databricks platform.

---

## Exercise 1: The Admiral's Question

**Difficulty:** Beginner
**Platform:** Local or Databricks
**Time:** 20-30 minutes

### Scenario

You've been handed a trained binary classifier that predicts whether a supply requisition will result in late delivery. The model was evaluated on a held-out test set and achieved AUC of 0.87. The program manager wants to brief the results to the supply depot commander.

Before the briefing, run the analysis the admiral would ask for.

### Task

1. Use `01_classification_pipeline.py` to generate data and train the Gradient Boosting classifier. Use the function `generate_requisition_data(n=25_000)` and the `build_and_train_pipeline()` function.

2. Using `stratified_eval_report()`, compute per-slice AUC for:
   - `priority_code` (the primary operational slice)
   - `supply_class`
   - `vendor_name` (if available from the raw data — re-engineer to include it)

3. Identify the worst-performing slice for each stratification. Write 2-3 sentences explaining why the model might underperform on that slice from first principles — not statistics, but operational reasoning about that specific category.

4. Suppose the briefing will include the following slide text: "The model achieves 87% AUC across all supply classes and priority levels." Rewrite this sentence to be operationally accurate given your findings.

**Deliverable:** Code that produces the stratified reports plus your written rewrite of the briefing statement.

---

## Exercise 2: Threshold Optimization for Real Costs

**Difficulty:** Intermediate
**Platform:** Local or Databricks
**Time:** 30-40 minutes

### Scenario

Your late delivery model is being deployed at a Navy supply depot that handles mixed Priority 01-15 requisitions. The operations officer has given you the following cost estimates:

- Expediting a requisition unnecessarily (false positive): $1,800 average cost (labor, shipping premium)
- Missing a genuinely late Priority 01 requisition (false negative): $45,000 average cost (operational impact, aircraft down-time equivalent)
- Missing a Priority 08-15 requisition (false negative): $800 average cost (minor delay, non-critical)

The model will be applied to all priority levels together in a single scoring run.

### Task

1. Train the classifier using `generate_requisition_data(n=25_000)`.

2. Using `find_operational_threshold()`, compute the optimal threshold using the costs given (use a blended FN cost — weighted average of Priority 01 and Priority 08-15 rates from your data).

3. Compare performance at three thresholds:
   - Default: 0.50
   - Your computed optimal threshold
   - A conservative threshold: 0.30

   For each threshold, report: false positive rate, false negative rate, total estimated cost (you'll need to estimate the number of FPs and FNs from the confusion matrix and multiply by costs).

4. Write a 3-sentence recommendation to the operations officer explaining which threshold to use and why. Quantify the cost difference between the default and your recommended threshold.

**Deliverable:** Code producing the three comparison tables plus your written recommendation.

---

## Exercise 3: Temporal Leakage Detection

**Difficulty:** Intermediate
**Platform:** Local or Databricks
**Time:** 40-50 minutes

### Scenario

A colleague trained a contract cost growth model that achieves R² of 0.94 on a random 80/20 train/test split. That number is suspicious — R² above 0.9 on real-world contract data is almost certainly a sign of something wrong.

You've been asked to investigate whether the model suffers from temporal leakage.

### Task

1. Generate contract data using `generate_contract_data(n=15_000)` from `02_regression_and_xgboost.py`.

2. Train two versions of an XGBoost regressor:
   - **Model A:** Random 80/20 train/test split (what the colleague did)
   - **Model B:** Temporal split — train on FY2018-2022, test on FY2023-2024

3. Report MAE, RMSE, and R² for both models. The difference between the two performance figures is the leakage estimate.

4. Now introduce a genuinely leaky feature: add `"vendor_lifetime_avg_growth"` to the feature set — the vendor's average cost growth ratio computed across all their contracts in the dataset (past and future). This is leaky because at prediction time you would not know future contracts. Retrain Model A with this feature and compare performance again.

5. Write a 2-3 paragraph explanation of:
   - Why the leaky feature improves performance on the random split
   - Why it would fail in production
   - How `temporal_train_test_split()` catches the problem where random splitting does not

**Deliverable:** Code for all three model variants plus your written explanation.

---

## Exercise 4: MLflow Experiment Tracking

**Difficulty:** Intermediate
**Platform:** Databricks (required for MLflow Model Registry); local for basic logging
**Time:** 45-60 minutes

### Scenario

Your team is running a model selection experiment for a readiness prediction classifier. Three analysts each tried a different model architecture. You need to set up a shared MLflow experiment that allows all three runs to be compared and the best one to be promoted to Staging.

### Task

1. Set up a local MLflow tracking server (use `mlflow.set_tracking_uri("./mlruns")` for local testing, or use the Databricks workspace path on platform).

2. Train three models in three separate MLflow runs within the same experiment (`"readiness_classifier_v2"`):
   - Run 1: Logistic Regression (name: `"lr_baseline"`)
   - Run 2: Random Forest with `n_estimators=200` (name: `"rf_200trees"`)
   - Run 3: Gradient Boosting (name: `"gbt_final"`)

   For each run, log: all model parameters, test AUC, average precision, F1 at default threshold, and the stratified AUC for at least two slices of your choice.

3. Using the MLflow Python client (`MlflowClient`), write a function `select_best_run(experiment_name, metric="test_roc_auc")` that:
   - Queries all runs in the experiment
   - Returns the run ID with the highest value of `metric`
   - Prints a comparison table of all runs

4. Call `promote_model_to_staging()` from `03_mlflow_and_batch_scoring.py` on the best run. Handle the case where the best model fails the AUC quality gate (force it to fail by setting `min_auc_threshold=0.99`).

**Deliverable:** Code for all three training runs, the `select_best_run()` function, and the promotion call with gate failure handling.

---

## Exercise 5: Build the Monitoring Job

**Difficulty:** Advanced
**Platform:** Databricks (required for Spark/Delta); local simulation acceptable
**Time:** 60-90 minutes

### Scenario

You've deployed the late delivery classifier to production. It scores new requisitions daily and writes results to `jupiter_catalog.gold.requisition_late_scores`. After 30 days of production scoring, you've been asked to build a monitoring notebook that runs weekly and alerts when something is wrong.

### Task

1. Simulate 60 days of scoring history. Write a function `simulate_scoring_history(n_days=60, baseline_flag_rate=0.18)` that generates a pandas DataFrame with columns: `scored_date` (daily dates), `requisition_id`, `late_delivery_probability`, `late_delivery_flag`. The flag rate should gradually drift upward after day 30 (simulating distribution shift in the underlying data).

2. Implement `check_prediction_drift()` (from `03_mlflow_and_batch_scoring.py`) using pandas instead of Spark (local simulation). Compare the last 14 days to the previous 30-day baseline.

3. Add a second check: input feature drift. Compute the mean of `vendor_on_time_rate` for requisitions scored in the last 14 days vs. the previous 30-day baseline. If the mean shifts by more than 0.05 (absolute), flag as drifted. This detects upstream data changes that haven't yet affected predictions but will soon.

4. Create a monitoring report function that returns a single dict with:
   - Whether output drift was detected
   - Whether input feature drift was detected
   - The specific drift values for both checks
   - A recommended action: `"no action"`, `"investigate"`, or `"retrain required"`

5. Write a short paragraph (3-4 sentences) explaining to a program manager why you need both input feature monitoring AND output score monitoring — and why output monitoring alone is not sufficient.

**Deliverable:** Working Python code for the simulation and all monitoring functions, plus your written explanation.

---

## Solutions

Solutions for all five exercises are in [solutions/solutions.md](./solutions/solutions.md).

Work through each exercise before reading solutions. The key judgments: does your stratified analysis surface operationally meaningful differences? Does your threshold calculation account for the specific cost asymmetry given? Does your temporal split actually prevent leakage? These are harder questions than "does the code run."
