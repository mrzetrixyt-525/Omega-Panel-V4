from __future__ import annotations
import os, re, secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from core import db
from core.config import BIND, PORT, SECRET_KEY, HOSTNAME, DEFAULT_ENGINE, DEFAULT_VCPUS, DEFAULT_MEMORY_MB, DEFAULT_DISK_GB, MAX_VPS_PER_USER, TIMEZONE, PANEL_URL, node_token
from core.i18n import LANGUAGES, tr
from core.os_profiles import OS_PROFILES, get_profile
from core.engine import action, remove, resize_instance, safe_name
from core.capabilities import snapshot
from core.provision import run_job

app=Flask(__name__)
app.secret_key=SECRET_KEY
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.getenv('OMEGA_COOKIE_SECURE','false').lower()=='true', MAX_CONTENT_LENGTH=1024*1024)
limiter=Limiter(key_func=get_remote_address, app=app, default_limits=["120 per minute"], storage_uri="memory://")

def current_lang(): return session.get('lang','en') if session.get('lang','en') in LANGUAGES else 'en'

def _(key): return tr(current_lang(),key)
app.jinja_env.globals['_']=_
app.jinja_env.globals['languages']=LANGUAGES
app.jinja_env.globals['host_name']=lambda: db.get_setting('host_name',HOSTNAME)

@app.before_request
def init_request():
    db.init_db()
    if 'csrf' not in session: session['csrf']=secrets.token_urlsafe(24)

def csrf_ok(): return secrets.compare_digest(request.form.get('csrf',''),session.get('csrf',''))
def require_csrf():
    if not csrf_ok(): abort(400,'Invalid CSRF token')

def login_required(fn):
    @wraps(fn)
    def wrapper(*a,**kw):
        if not session.get('uid'): return redirect(url_for('login', next=request.path))
        return fn(*a,**kw)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*a,**kw):
        if not session.get('uid') or session.get('role')!='admin': abort(403)
        return fn(*a,**kw)
    return wrapper

def bootstrap_admin():
    db.init_db()
    from core.config import DATA_DIR
    with db.db() as con:
        exists=con.execute("SELECT 1 FROM users LIMIT 1").fetchone()
    if exists: return None
    username=os.getenv('OMEGA_ADMIN_USERNAME','admin').strip() or 'admin'
    password=os.getenv('OMEGA_ADMIN_PASSWORD')
    generated=False
    if not password:
        password=secrets.token_urlsafe(14); generated=True
    db.create_user(username,password,'admin',max_vps=999999)
    cred=DATA_DIR/'first_admin_credentials.txt'
    DATA_DIR.mkdir(parents=True,exist_ok=True)
    cred.write_text(f"Username: {username}\nPassword: {password}\nCreated: {db.utcnow()}\n",encoding='utf-8')
    try: os.chmod(cred,0o600)
    except PermissionError: pass
    return (username,password,cred,generated)

@app.route('/')
def index():
    if session.get('uid'): return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/lang/<lang>')
def set_lang(lang):
    if lang in LANGUAGES: session['lang']=lang
    return redirect(request.referrer or url_for('index'))

@app.route('/register',methods=['GET','POST'])
@limiter.limit('6 per minute',methods=['POST'])
def register():
    if request.method=='POST':
        require_csrf(); username=request.form.get('username','').strip(); password=request.form.get('password','')
        try:
            uid=db.create_user(username,password)
            session.update(uid=uid,username=username,role='user'); return redirect(url_for('dashboard'))
        except Exception as e: flash(str(e),'danger')
    return render_template('auth.html', mode='register')

@app.route('/login',methods=['GET','POST'])
@limiter.limit('8 per minute',methods=['POST'])
def login():
    if request.method=='POST':
        require_csrf(); user=db.verify_user(request.form.get('username',''),request.form.get('password',''))
        if not user: flash('Invalid username or password','danger')
        else:
            session.clear(); session.update(uid=user['id'],username=user['username'],role=user['role']); session['csrf']=secrets.token_urlsafe(24)
            return redirect(request.args.get('next') or url_for('dashboard'))
    return render_template('auth.html', mode='login')

@app.route('/logout',methods=['POST'])
@login_required
def logout(): require_csrf(); session.clear(); return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    vps=db.list_vps_for_user(session['uid']); jobs=db.list_jobs_for_user(session['uid']); caps=snapshot()
    return render_template('dashboard.html',vps=vps,jobs=jobs,caps=caps,os_profiles=OS_PROFILES,default_vcpus=int(db.get_setting('default_vcpus',DEFAULT_VCPUS)),default_memory=int(db.get_setting('default_memory_mb',DEFAULT_MEMORY_MB)),default_disk=int(db.get_setting('default_disk_gb',DEFAULT_DISK_GB)))

@app.route('/vps/create',methods=['POST'])
@login_required
def create_vps():
    require_csrf()
    username=session['username']; user=db.get_user(session['uid']); nodes=[n for n in db.list_nodes() if n['enabled']]
    node=nodes[0] if nodes else None
    if not node:
        token=node_token(); nid=db.ensure_local_node(token); node=db.get_node(nid)
    active=db.count_vps(session['uid'])
    limit=int(user['max_vps']) if user else MAX_VPS_PER_USER
    if active>=limit: flash(f'VPS limit reached ({limit}). Ask an admin to increase your quota.','warning'); return redirect(url_for('dashboard'))
    name=re.sub(r'[^a-z0-9-]+','-',request.form.get('name','').lower()).strip('-')
    try: safe_name(name)
    except Exception as e: flash(str(e),'danger'); return redirect(url_for('dashboard'))
    os_slug=request.form.get('os','ubuntu-24.04')
    engine=request.form.get('engine','container')
    try: get_profile(os_slug)
    except Exception as e: flash(str(e),'danger'); return redirect(url_for('dashboard'))
    if engine not in ('container','vm'): engine='container'
    try:
        vcpus=max(1,min(64,int(request.form.get('vcpus',DEFAULT_VCPUS))))
        memory=max(512,min(262144,int(request.form.get('memory',DEFAULT_MEMORY_MB))))
        disk=max(5,min(4096,int(request.form.get('disk',DEFAULT_DISK_GB))))
        vps_id=db.create_vps(session['uid'],node['id'],name,os_slug,engine,vcpus,memory,disk,name)
        jid=db.create_job(vps_id,'provision','Queued for VPS creation')
        flash('VPS creation started. Live progress is shown below.','info')
    except Exception as e: flash(str(e),'danger')
    return redirect(url_for('dashboard'))

@app.route('/vps/<int:vps_id>/<op>',methods=['POST'])
@login_required
def vps_action(vps_id,op):
    require_csrf(); v=db.get_vps(vps_id)
    if not v or (v['user_id']!=session['uid'] and session['role']!='admin'): abort(404)
    try:
        if op=='delete':
            remove(v['name']); db.delete_vps(vps_id); flash('VPS deleted.','success')
        elif op in ('start','stop','restart'):
            st=action(v['name'],op); db.update_vps(vps_id,state=st.get('state','offline'),ip_address=st.get('ip')); flash(f'VPS {op} completed.','success')
        else: abort(404)
    except Exception as e:
        db.update_vps(vps_id,state='error'); flash(str(e),'danger')
    return redirect(url_for('dashboard'))

@app.route('/vps/<int:vps_id>')
@login_required
def vps_detail(vps_id):
    v=db.get_vps(vps_id)
    if not v or (v['user_id']!=session['uid'] and session['role']!='admin'): abort(404)
    jobs=db.list_jobs_for_user(v['user_id'],25); return render_template('vps.html',vps=v,jobs=jobs)

@app.route('/api/jobs/<int:job_id>')
@login_required
def api_job(job_id):
    j=db.get_job(job_id)
    if not j: abort(404)
    v=db.get_vps(j['vps_id']) if j['vps_id'] else None
    if not v or (v['user_id']!=session['uid'] and session['role']!='admin'): abort(403)
    return jsonify({**dict(j),'details':__import__('json').loads(j['details'] or '{}')})

@app.route('/api/node')
@login_required
def api_node():
    return jsonify(snapshot())

@app.route('/healthz')
def healthz():
    db.init_db(); return jsonify({'ok':True,'service':'omega-panel','version':'V4 Stable','hostname':db.get_setting('host_name',HOSTNAME)})

@app.route('/admin')
@admin_required
def admin():
    return render_template('admin.html',nodes=db.list_nodes(),users=db.all_users(),vps=db.list_all_vps(),caps=snapshot())

@app.route('/admin/settings',methods=['POST'])
@admin_required
def admin_settings():
    require_csrf()
    pairs={'host_name':'host_name','default_engine':'default_engine','default_vcpus':'default_vcpus','default_memory_mb':'default_memory_mb','default_disk_gb':'default_disk_gb','max_vps_per_user':'max_vps_per_user','auto_update':'auto_update'}
    for form_key,key in pairs.items():
        value=request.form.get(form_key)
        if value is not None: db.set_setting(key,value)
    flash('Settings saved.','success'); return redirect(url_for('admin'))

@app.route('/admin/users/<int:user_id>/quota',methods=['POST'])
@admin_required
def admin_quota(user_id):
    require_csrf()
    try: db.set_user_quota(user_id,int(request.form.get('max_vps','1'))); flash('User quota updated.','success')
    except Exception as e: flash(str(e),'danger')
    return redirect(url_for('admin'))

@app.route('/admin/vps/<int:vps_id>/resources',methods=['POST'])
@admin_required
def admin_vps_resources(vps_id):
    require_csrf()
    v=db.get_vps(vps_id)
    if not v: abort(404)
    try:
        cpu=max(1,int(request.form['vcpus'])); mem=max(512,int(request.form['memory'])); disk=max(5,int(request.form['disk']))
        resize_instance(v['name'],cpu,mem,disk)
        db.update_vps(vps_id,vcpus=cpu,memory_mb=mem,disk_gb=disk)
        flash('VPS resources applied to the Incus instance.','success')
    except Exception as e: flash(str(e),'danger')
    return redirect(url_for('admin'))

@app.route('/vps/<int:vps_id>/pterodactyl',methods=['POST'])
@admin_required
def install_pterodactyl(vps_id):
    require_csrf(); v=db.get_vps(vps_id)
    if not v: abort(404)
    try:
        from core.pterodactyl import install_pterodactyl as run_ptero
        result=run_ptero(v['name'],v['os_slug'],request.form.get('domain','').strip(),request.form.get('email','').strip())
        flash('Pterodactyl installation finished. Review the guest installer output and configure TLS/admin settings.','success')
    except Exception as e: flash(str(e),'danger')
    return redirect(url_for('vps_detail',vps_id=vps_id))

@app.context_processor
def context():
    return {'user': db.get_user(session['uid']) if session.get('uid') else None, 'csrf':session.get('csrf',''), 'timezone':TIMEZONE, 'panel_url':PANEL_URL}

if __name__=='__main__':
    db.init_db(); boot=bootstrap_admin()
    if boot:
        print(f"Omega Panel first admin: {boot[0]} / {boot[1]}")
        print(f"Credentials file: {boot[2]}")
    db.ensure_local_node(node_token())
    app.run(host=BIND,port=PORT,debug=False)
