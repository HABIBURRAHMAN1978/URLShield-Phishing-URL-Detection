"""COM6011 V7 single-source offline features (training + deployed model)."""
import numpy as np
from scipy.sparse import csr_matrix,hstack
from url_engine import parse_url,host_features,NUMERIC_FEATURES,full_url_features,FULL_EXTRA_FEATURES
HOST_COLUMNS=list(NUMERIC_FEATURES)
FULL_EXCLUDED={'url_length','scheme_https','scheme_http','scheme_absent','url_num_slashes','url_num_colons','full_entropy','path_to_url_ratio','query_to_url_ratio'}
FULL_COLUMNS=HOST_COLUMNS+[k for k in FULL_EXTRA_FEATURES if k not in FULL_EXCLUDED]
def texts_and_numeric(urls):
 parsed=[parse_url(str(u)) for u in urls]
 hosts=[p['host_model'] for p in parsed]
 canonical=[p['host_model']+(p['parsed'].path or '')+('?' + p['parsed'].query if p['parsed'].query else '')+('#'+p['parsed'].fragment if p['parsed'].fragment else '') for p in parsed]
 cache={h:host_features(h) for h in set(hosts)}
 hostnum=np.asarray([[cache[h][key] for key in HOST_COLUMNS] for h in hosts],dtype=np.float32)
 fullrows=[full_url_features(u) for u in urls]
 fullnum=np.asarray([[*([cache[h][k] for k in HOST_COLUMNS]),*([f[k] for k in FULL_COLUMNS[len(HOST_COLUMNS):]])] for h,f in zip(hosts,fullrows)],dtype=np.float32)
 return hosts,canonical,hostnum,fullnum

def transform_urls(urls,vectorizer=None,scaler=None,mode='host_numeric'):
 hosts,fulltext,hostnum,fullnum=texts_and_numeric(urls)
 if mode=='host_numeric':return hostnum
 if mode=='host_scaled':return scaler.transform(hostnum).astype(np.float32)
 if mode=='full_numeric':return fullnum
 if mode=='full_scaled':return scaler.transform(fullnum).astype(np.float32)
 if mode=='full_char':return vectorizer.transform(fulltext)
 if mode=='full_hybrid':
  text=vectorizer.transform(fulltext)
  n=scaler.transform(fullnum).astype(np.float32)
  return hstack([text,csr_matrix(n*.25)],format='csr',dtype=np.float32)
 raise ValueError('Unknown model feature mode: '+str(mode))

def get_scores(model,X):
 i=list(model.classes_).index(1)
 return np.asarray(model.predict_proba(X)[:,i],dtype=np.float64)
