# URLShield V7 | COM6011 offline phishing URL screening

## Start on Windows CMD
In the exported `COM6011_V7/app` directory:

```cmd
py -3.12 -m pip install -r requirements.txt
py -3.12 -m streamlit run app.py
```

Open http://localhost:8501. Submitted URLs are analysed as text only; the website never visits them or calls remote services.

## Models and data
Four approved classifiers are trained and compared: Logistic Regression, Random Forest, Decision Tree and Naive Bayes. Candidate inputs include a hostname-only baseline, actual full-URL lexical features, and character n-grams. A full URL candidate can use URL paths/queries. If all full-URL models fail validation/external candidate-domain robustness guards, a hostname baseline may be selected; if so, the app transparently states that paths/queries are not used by the deployed ML model.

- PhiUSIIL: URL and original label (0 phishing, 1 legitimate), correctly remapped.
- ISCX historical benign full URL list: supplementary historical benign examples with paths/queries, not guaranteed currently safe.
- PhishTank: separate phishing-positive-labelled diagnostic (not used as training ground truth).
- Majestic: *unlabelled* candidate-domain robustness probe, plus separate held-aside sample; not proven clean and never reported as true benign ground truth.

Candidate-domain flagging rates are not measured false-positive rates. The selection policy also tests overall FPR and the historical benign-path subgroup on the labelled validation sample. All model/threshold decisions are locked **without looking at held-out test labels**. Source bias still exists and figures may differ across dataset versions. Do not compare V6/V7 headline accuracy as a matched-split experiment.

## Limitations and evidence
Model scores are uncalibrated and do not represent verified live phishing probabilities. A URL that is not flagged might still be dangerous. HTTPS is recorded as an observation but is excluded from predictive input in scheme-neutral variants because scheme/source bias affected earlier iterations. The site performs no URL crawling, DNS, WHOIS or live blacklist queries and uses no participants. See the parent ZIP's `audit`, `testing`, `figures`, `tables`, `docs`, and `models` files.

The app has individual screening, CSV batch screening up to 500 URLs, session-local history, URL observations, a model panel, and safety guidance. The bundled Public Suffix List snapshot retains attribution and MPL-2.0 provenance.
