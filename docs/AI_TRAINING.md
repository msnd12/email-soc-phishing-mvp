# URL AI Training

The MVP now includes an offline URL phishing classifier trainer. It downloads:

- PhishTank verified online phishing URLs
- Tranco latest top-million domains

The default target is a balanced dataset:

- 300,000 phishing URL examples
- 300,000 benign Tranco URL examples

## Important PhishTank Limit

PhishTank's public `online-valid.csv` feed only contains currently online, verified phish. On many days this feed may contain fewer than 300,000 usable rows. The trainer does not duplicate rows or fake extra data.

If the public feed has fewer than 300,000 rows, use one of these options:

1. Provide a larger local PhishTank export:

   ```powershell
   $env:PHISHTANK_DATASET_PATH="C:\path\to\phishtank-large.csv"
   npm.cmd run ai:train
   ```

2. Lower the sample size for development:

   ```powershell
   $env:AI_TRAINING_SAMPLE_SIZE="50000"
   npm.cmd run ai:train
   ```

3. Allow a smaller PhishTank sample only for local experimentation:

   ```powershell
   $env:AI_TRAINING_ALLOW_SMALLER_PHISHTANK="true"
   npm.cmd run ai:train
   ```

Do not use option 3 for acceptance testing if the requirement is exactly 300k phishing examples.

## Recommended 300k Training Command

From the repository root:

```powershell
$env:PHISHTANK_APP_KEY="your-phishtank-app-key"
$env:PHISHTANK_USER_AGENT="email-soc-phishing-mvp/0.1 your-email@example.com"
$env:AI_TRAINING_SAMPLE_SIZE="300000"
$env:URL_AI_MODEL_PATH="models/url-phishing-model.json"
npm.cmd run ai:train
```

The trainer writes:

```text
backend/models/url-phishing-model.json
```

The backend loads that model automatically if `URL_AI_MODEL_PATH=models/url-phishing-model.json`.

## What the Model Learns

The trainer uses explainable lexical URL features, including:

- URL length
- hostname length
- path/query length
- digit ratio
- entropy
- IP host
- punycode
- suspicious TLD
- URL shortener
- brand lookalike signal
- risk keyword count
- encoded or hex-looking tokens

At runtime, the risk engine adds reasons such as:

```text
AI URL model predicts 87% phishing probability for login-example.click
AI feature signal: suspicious_tld
AI feature signal: brand_lookalike
```

## Training From `vonDataset20180426.dill`

If you have `C:\\path\\to\\vonDataset20180426.dill`, use this trainer for better accuracy on the 1.55M labeled URL dataset:

```powershell
$env:VON_DATASET_PATH="C:\path\to\vonDataset20180426.dill"
$env:URL_AI_MODEL_PATH="models/url-phishing-model.json"
$env:VON_AI_TARGET_MAX_FPR="0.02"
npm.cmd run ai:train:von
```

The labels in this dataset are treated as:

```text
0 = legitimate
1 = phishing
```

The trainer calibrates the model threshold against the validation set to target a false-positive rate of 2% by default. This matters because a phishing detector that marks normal Microsoft, Google, or banking links as Critical is operationally noisy.

You can make it stricter:

```powershell
$env:VON_AI_TARGET_MAX_FPR="0.01"
npm.cmd run ai:train:von
```

For better accuracy, use the hashed character n-gram trainer:

```powershell
$env:VON_DATASET_PATH="C:\path\to\vonDataset20180426.dill"
$env:URL_AI_MODEL_PATH="models/url-phishing-model.json"
$env:VON_AI_TARGET_MAX_FPR="0.02"
npm.cmd run ai:train:von-ngram
```

This is the recommended trainer for the dashboard because it learns URL character patterns across the whole string instead of only learning fixed character positions.

## Smoke Test

For a quick trainer check:

```powershell
$env:AI_TRAINING_SAMPLE_SIZE="50"
$env:URL_AI_MODEL_PATH="models/url-phishing-model-smoke.json"
npm.cmd run ai:train
```

Delete the smoke model afterward so production does not use it.
