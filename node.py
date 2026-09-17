from __future__ import annotations
import argparse, hmac, os
from flask import Flask, jsonify, request
from core.config import NODE_BIND, NODE_PORT, NODE_NAME, node_token
from core.capabilities import snapshot
from core.engine import action, remove
from core.provision import run_job, reconcile_running
from core import db

app=Flask(__name__)
TOKEN=node_token()

def auth(): return hmac.compare_digest(request.headers.get('Authorization','').removeprefix('Bearer ').strip(),TOKEN)
@app.before_request

def guard():
    if request.path=='/health' : return None
    if not auth(): return jsonify({'ok':False,'error':'unauthorized'}),401

@app.get('/health')
def health(): return jsonify({'ok':True,'node':NODE_NAME})
@app.get('/capabilities')
def capabilities(): return jsonify(snapshot())
@app.get('/resources')
def resources(): return jsonify(snapshot())
@app.post('/v1/vps/<int:vps_id>/<op>')
def vps_op(vps_id,op):
    v=db.get_vps(vps_id)
    if not v: return jsonify({'ok':False,'error':'not found'}),404
    try:
        st=action(v['name'],op); db.update_vps(vps_id,state=st['state'],ip_address=st.get('ip')); return jsonify({'ok':True,**st})
    except Exception as e: return jsonify({'ok':False,'error':str(e)}),400

@app.post('/v1/reconcile')
def reconcile():
    reconcile_running(); return jsonify({'ok':True})

if __name__=='__main__':
    db.init_db(); app.run(host=NODE_BIND,port=NODE_PORT,debug=False)
