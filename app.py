"""COM6011: offline URL-text screening prototype. Never visits submitted URLs."""
import io,json,time,html
from pathlib import Path
import numpy as np
import pandas as pd
import joblib
import streamlit as st
from url_engine import parse_url,full_url_observations,NUMERIC_FEATURES
from feature_pipeline import transform_urls,get_scores

BASE=Path(__file__).resolve().parent
st.set_page_config(page_title='URLShield | Offline Phishing URL Screening',page_icon='🛡️',layout='wide',initial_sidebar_state='expanded')

@st.cache_resource(show_spinner=False)
def load_artifacts():
 meta=json.loads((BASE/'model_info.json').read_text(encoding='utf-8'))
 artifacts=joblib.load(BASE/'selected_model.joblib')
 return meta,artifacts

info,assets=load_artifacts()
model=assets['model']; vectorizer=assets.get('vectorizer');scaler=assets.get('scaler');feature_mode=assets['mode'];threshold=float(info['threshold'])

def evaluate_one(raw):
 d=parse_url(raw)
 x=transform_urls([raw],vectorizer=vectorizer,scaler=scaler,mode=feature_mode)
 score=float(get_scores(model,x)[0])
 return {'url':d['raw'],'host':d['host_model'],'score':score,'flagged':score>=threshold,'observations':full_url_observations(raw)}

st.markdown('''<style>
html,body,[class*="css"],div[data-testid="stAppViewContainer"]{font-family:system-ui,sans-serif!important;}
.stApp{background:radial-gradient(ellipse 1000px 480px at 50% -180px,#123e63 0,transparent 75%),#08121f;color:#edf5fb}
[data-testid="stSidebar"]{background:#0c1d30;border-right:1px solid #20394f;}
[data-testid="stHeader"]{background:transparent;}
.block-container{padding-top:2rem;max-width:1250px;}
.hero{background:linear-gradient(115deg,rgba(23,64,95,.88),rgba(9,32,49,.96)),radial-gradient(circle at top right,#155e75,transparent 60%);padding:30px 36px;border:1px solid #28516a;border-radius:23px;margin-bottom:20px;box-shadow:0 20px 50px #0002;}
.kicker{font-size:12px;text-transform:uppercase;letter-spacing:2.6px;color:#6fe5c1;font-weight:800;margin-bottom:9px}
.hero h1{font-family:system-ui,sans-serif;font-size:40px;font-weight:800;letter-spacing:-1.1px;margin:0 0 10px;color:#f1fcff}
.hero p{font-size:15px;line-height:1.65;color:#c5d9e8;max-width:800px}
.tag{display:inline-block;background:#103e48;color:#75ecd0;padding:7px 12px;border:1px solid #256b6d;border-radius:22px;font-size:12px;margin-right:8px;margin-top:10px}
.panel{border:1px solid #24455f;background:#0c2235;border-radius:20px;padding:20px 24px;margin:12px 0}
.panel h3{margin:0 0 8px;color:#f0f9ff;font-family:system-ui}
.micro{font-size:12px;line-height:1.55;color:#94b6cb}
.status-red{background:#42212a;border:1px solid #bd5367;color:#ffcad1;border-radius:16px;padding:18px 22px;font-size:17px;font-weight:700}
.status-green{background:#113c39;border:1px solid #2b8d7a;color:#bbffdf;border-radius:16px;padding:18px 22px;font-size:17px;font-weight:700}
.num{font-size:33px;color:#ebfbff;font-weight:800;font-family:system-ui}
[data-testid="stMetric"]{background:#0e283d;border:1px solid #28506a;border-radius:15px;padding:14px 15px;}
[data-testid="stMetricValue"]{color:#f1f9ff!important;font-weight:800!important;}
.stButton>button[kind="primary"]{background:linear-gradient(100deg,#1ac5aa,#178bb2)!important;color:#061722!important;font-weight:800!important;border-radius:12px!important;border:0!important;padding:10px 20px!important;}
.stTextInput input,.stTextArea textarea{background:#0f2940;color:#effaff;border:1px solid #30516c;border-radius:11px;}
[data-testid="stFileUploader"]{background:#0c2235;border:1px dashed #376983;border-radius:14px;padding:10px}
[data-testid="stTabs"] [data-baseweb="tab-list"]{gap:15px}
[data-testid="stTabs"] button{color:#c3e4ec}
hr{border-color:#25435a}
@media(max-width:720px){.hero{padding:20px}.hero h1{font-size:28px}}
</style>''',unsafe_allow_html=True)

st.markdown('''<section class="hero"><div class="kicker">COM6011 • MACHINE LEARNING ARTEFACT</div>
<h1>URL<span style="color:#69e3bf">Shield</span> <span style="font-weight:400;font-size:21px;color:#add2e3">/ Offline Security Screening</span></h1>
<p>Analyse complete URL text with validation-selected ML representations in a research prototype. Input is analysed locally as text only — no websites are visited and no live domain reputations are checked.</p>
<span class="tag">✦ Offline by design</span><span class="tag">✦ Machine learning comparison</span><span class="tag">✦ Explainable observations</span></section>''',unsafe_allow_html=True)

with st.sidebar:
 st.markdown('### 🛡️ URLShield')
 st.caption('COM6011 practical computing prototype')
 st.divider()
 st.markdown('**Selected estimator**')
 st.write(info['model_name'])
 st.markdown('**Input representation**')
 st.write(info['feature_mode_label'])
 st.markdown('**Decision threshold**')
 st.write(f"{threshold:.0%} (selected on validation)")
 st.divider()
 st.info('**Model screening score ≠ verified risk probability.** A URL not flagged by the model may still be dangerous.')
 st.caption('Offline URL-text inspection · No fetch, DNS, WHOIS, API lookup, browser navigation or data submission.')
 with st.expander('Dataset & evaluation notes'):
  st.write('Training uses PhiUSIIL labels and historical ISCX benign full URLs (labels may be outdated). PhishTank provides a phishing-positive external check; Majestic is a domain list, NOT verified benign ground truth.')
  st.write('Model input depends on validation-selected feature view (shown above). Full URL candidates use paths and queries; hostname baseline does not. Source and structure bias remain limitations.')

check_tab,batch_tab,about_tab=st.tabs(['🔎 Individual URL','📚 Batch screening','📊 Model & limitations'])
with check_tab:
 st.markdown('#### Screen a URL or domain')
 st.caption('Example: https://www.example.com/account/login  • Input is never opened.')
 with st.form('main_form'):
  url=st.text_input('URL / domain',value='https://www.google.com',placeholder='https://example.com/login')
  submitted=st.form_submit_button('Analyse URL',type='primary',use_container_width=True)
 if submitted:
  try:
   start=time.perf_counter()
   r=evaluate_one(url)
   elapsed=(time.perf_counter()-start)*1000
   if 'history' not in st.session_state:st.session_state.history=[]
   st.session_state.history.insert(0,{'URL':r['url'],'Hostname':r['host'],'Screening score':round(r['score'],4),'Flagged':r['flagged']})
   st.session_state.history=st.session_state.history[:25]
   if r['flagged']:
    st.markdown('<div class="status-red">⚠️ Model flagged URL-text patterns — exercise caution</div>',unsafe_allow_html=True)
   else:
    st.markdown('<div class="status-green">✓ No model flag at this threshold — safety NOT verified</div>',unsafe_allow_html=True)
   a,b,c=st.columns(3)
   a.metric('Model screening score',f"{r['score']:.1%}")
   b.metric('Decision threshold',f'{threshold:.0%}')
   c.metric('Local processing time',f'{elapsed:.1f} ms')
   st.progress(max(0.,min(1.,r['score'])))
   obs_tab,tech_tab,advice_tab=st.tabs(['🧩 URL observations','⚙️ Technical details','✅ Safety guidance'])
   with obs_tab:
    for item in r['observations']:st.write('• '+item)
    st.caption('These descriptive indicators are NOT explanations of the selected model, nor independent verification.')
   with tech_tab:
    st.code(r['host'],language='text')
    st.write('**Feature representation:**',info['feature_mode_label'])
    st.write('**Estimator:**',info['model_name'])
    st.write('**Prediction:**', 'flagged' if r['flagged'] else 'not flagged')
    st.warning("Selected representation: " + str(info["feature_mode_label"]) + ". " + ("URL path/query features contribute to this model. " if info.get("full_url_model") else "This selected hostname baseline does not use path/query; they are advisory only. ") + "Scores are uncalibrated; no URL is verified safe.")
   with advice_tab:
    st.markdown('**Before trusting any link:** verify the domain through a known official channel, avoid entering credentials into unexpected forms, and check links received in unsolicited messages.')
    st.markdown('**If you suspect phishing:** do not enter passwords or payment details. Report the suspicious URL to your organisation or appropriate service.')
   st.caption('Research demonstration only. NOT a security guarantee or production phishing protection.')
  except Exception as exc:
   st.error(f'URL could not be analysed: {exc}')
 if st.session_state.get('history'):
  with st.expander('Recent results in this browser session (not saved to disk)'):
   st.dataframe(pd.DataFrame(st.session_state.history),use_container_width=True,hide_index=True)
   st.download_button('Download session results',pd.DataFrame(st.session_state.history).to_csv(index=False).encode('utf-8'),file_name='local_url_screening.csv',mime='text/csv')

with batch_tab:
 st.markdown('#### Batch URL screening')
 st.caption('Upload a local CSV with a URL column. Maximum 500 entries per batch. No uploaded URL is fetched.')
 file=st.file_uploader('CSV file',type=['csv'],key='batch_file')
 if file is not None:
  try:
   df=pd.read_csv(file,dtype=str,keep_default_na=False)
   options=[c for c in df.columns if c.lower().strip() in ('url','urls','link','website')]
   col=st.selectbox('Select URL column',df.columns,index=df.columns.get_loc(options[0]) if options else 0)
   if st.button('Screen CSV',type='primary'):
    if len(df)>500:st.error('Maximum 500 URLs per batch. Please split the file.')
    else:
     out=[]
     progress=st.progress(0)
     for i,raw in enumerate(df[col].astype(str).tolist()):
      try:
       r=evaluate_one(raw)
       out.append({'URL':r['url'],'Hostname':r['host'],'Model screening score':round(r['score'],5),'Flagged':r['flagged'],'Error':''})
      except ValueError as ex:
       out.append({'URL':raw,'Hostname':'','Model screening score':np.nan,'Flagged':'','Error':str(ex)})
      progress.progress((i+1)/max(1,len(df)))
     outdf=pd.DataFrame(out)
     st.session_state.batch_results=outdf
     st.success(f"Screened {len(outdf)} rows offline. Predictions are research estimates, not URL safety verification.")
   if 'batch_results' in st.session_state:
    outdf=st.session_state.batch_results
    st.dataframe(outdf,use_container_width=True,hide_index=True)
    st.download_button('Download batch results',outdf.to_csv(index=False).encode('utf-8'),file_name='urlshield_batch_results.csv',mime='text/csv')
  except Exception as exc:st.error(f'CSV could not be processed: {exc}')

with about_tab:
 st.markdown('#### Reproducible evaluation')
 held=info.get('heldout_metrics',{})
 if held:
  a,b,c=st.columns(3)
  a.metric('Held-out accuracy',f"{held.get('accuracy',0):.1%}")
  b.metric('Phishing recall',f"{held.get('recall',0):.1%}")
  c.metric('False-positive rate',f"{held.get('fpr',0):.1%}")
  st.caption(f"Registered-domain-disjoint mixed-source labelled test: {held.get('n',0):,} URLs. Results are not independent real-world validation.")
 st.markdown('''**Limitations:** source bias, domain distribution shift, incomplete independent benign labels and missed phishing attacks. Path/query are used only if a full-URL feature candidate is selected; review the feature mode displayed. A site can change after model training. The URL is not opened or verified.

**Ethics:** public secondary data, local text feature extraction only; no questionnaires or participant data collection. No crawls, DNS lookups, WHOIS or live URL requests.''')
 st.caption('Machine-learning research prototype · COM6011 · Offline-only design')
