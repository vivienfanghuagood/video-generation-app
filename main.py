# main.py
import os
import time
import hashlib
import re
from typing import Optional, Tuple, Dict

from fastapi import FastAPI, HTTPException, Query, Header
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from kubernetes import client, config
from kubernetes.client import (
    V1Pod, V1PodSpec, V1Container, V1ObjectMeta, V1Service, V1ServiceSpec,
    V1ServicePort, V1ContainerPort, V1SecurityContext
)
from kubernetes.client.rest import ApiException

# -----------------------------
# Configuration (overridable via env)
# -----------------------------
NAMESPACE = os.getenv("NAMESPACE", "default")

# Service type: NodePort (default) or LoadBalancer
SERVICE_TYPE = os.getenv("SERVICE_TYPE", "NodePort")  # NodePort | LoadBalancer

# Notebook image (fixed)
NOTEBOOK_IMAGE = os.getenv("NOTEBOOK_IMAGE", "jupyter/minimal-notebook:lab-4.2.5")

# In-container ports: A=Jupyter, B=user app
CONTAINER_PORT_A = int(os.getenv("CONTAINER_PORT_A", "8888"))
CONTAINER_PORT_B = int(os.getenv("CONTAINER_PORT_B", "9000"))

# Service "port" (LB mode: exposed port; NodePort mode: clusterIP servicePort)
SERVICE_PORT_A = int(os.getenv("SERVICE_PORT_A", "8080"))
SERVICE_PORT_B = int(os.getenv("SERVICE_PORT_B", "9000"))

# Optional explicit NodePort; if unset -> let K8s auto-assign
def env_int_or_none(name: str):
    v = os.getenv(name)
    if v is None or str(v).strip() == "":
        return None
    try:
        return int(v)
    except ValueError:
        return None

NODE_PORT_A = env_int_or_none("NODE_PORT_A")  # None -> auto-assign
NODE_PORT_B = env_int_or_none("NODE_PORT_B")

# Wait timeout for external address readiness (seconds)
WAIT_TIMEOUT = int(os.getenv("WAIT_TIMEOUT", "180"))

# Resource name prefix
NAME_PREFIX = os.getenv("NAME_PREFIX", "video")

# Labels/Annotations
APP_LABEL_KEY = "app"
APP_LABEL_VAL = "video-task"
OWNER_LABEL_KEY = "owner"               # sanitized email
EMAIL_ANNOTATION_KEY = "video/email"

# Email domain allow-list, e.g. "example.com,corp.local"
ALLOWED_EMAIL_DOMAINS = {d.strip().lower() for d in os.getenv("ALLOWED_EMAIL_DOMAINS", "").split(",") if d.strip()}

# Admin token for cleanup (DELETE). If empty, cleanup API disabled.
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

# Optional CORS (if hosting UI elsewhere). Same-origin can keep "*".
ALLOW_ORIGINS = [o.strip() for o in os.getenv("ALLOW_ORIGINS", "*").split(",") if o.strip()]

# Optional EXA API key to pass into container env
EXA_API_KEY = os.getenv("EXA_API_KEY", "")

# -----------------------------
# App bootstrap
# -----------------------------
app = FastAPI(title="K8s Video Task API", version="1.4.1")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def load_kube_config():
    """Prefer in-cluster config, fallback to local kubeconfig."""
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()

load_kube_config()
core = client.CoreV1Api()

# -----------------------------
# Utilities
# -----------------------------
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def check_email_allowed(email: str, for_cleanup: bool = False):
    """
    Validate email format and (if configured) domain allow-list.
    Special-case: for cleanup, 'all' is allowed.
    """
    if for_cleanup and email.lower() == "all":
        return

    if not EMAIL_REGEX.match(email):
        raise HTTPException(status_code=400, detail="Invalid email format")

    if ALLOWED_EMAIL_DOMAINS:
        domain = email.split("@")[-1].lower()
        if domain not in ALLOWED_EMAIL_DOMAINS:
            raise HTTPException(status_code=403, detail=f"Email domain '{domain}' is not allowed")

def require_admin(token_from_header: Optional[str]):
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=503, detail="Admin token not configured on server")
    if token_from_header != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden: admin token invalid")

def sanitize_name(s: str, max_len: int = 50) -> str:
    base = ''.join(ch if ch.isalnum() else '-' for ch in s.lower())
    base = base.strip('-')
    if len(base) > max_len:
        base = base[:max_len].strip('-')
    return base or "user"

def name_for_email(email: str) -> Tuple[str, str]:
    owner = sanitize_name(email, 30)
    digest = hashlib.sha1(email.encode()).hexdigest()[:8]
    pod_name = f"{NAME_PREFIX}-pod-{owner}-{digest}"
    svc_name = f"{NAME_PREFIX}-svc-{owner}-{digest}"
    return pod_name[:63], svc_name[:63]

def find_existing_service(email: str) -> Optional[V1Service]:
    owner = sanitize_name(email, 30)
    label_selector = f"{APP_LABEL_KEY}={APP_LABEL_VAL},{OWNER_LABEL_KEY}={owner}"
    svcs = core.list_namespaced_service(namespace=NAMESPACE, label_selector=label_selector)
    for svc in svcs.items:
        ann = svc.metadata.annotations or {}
        if ann.get(EMAIL_ANNOTATION_KEY) == email:
            return svc
    return None

def find_existing_pod(email: str) -> Optional[V1Pod]:
    owner = sanitize_name(email, 30)
    label_selector = f"{APP_LABEL_KEY}={APP_LABEL_VAL},{OWNER_LABEL_KEY}={owner}"
    pods = core.list_namespaced_pod(namespace=NAMESPACE, label_selector=label_selector)
    return pods.items[0] if pods.items else None

def get_node_external_ip() -> Optional[str]:
    """Prefer Node ExternalIP; fallback to InternalIP."""
    nodes = core.list_node().items
    chosen_internal = None
    for n in nodes:
        addrs = {addr.type: addr.address for addr in n.status.addresses or []}
        if "ExternalIP" in addrs:
            return addrs["ExternalIP"]
        if not chosen_internal and "InternalIP" in addrs:
            chosen_internal = addrs["InternalIP"]
    return chosen_internal

def external_access_for_service(svc: V1Service) -> Tuple[Optional[str], Optional[int], Optional[int]]:
    ports = {p.name: p for p in svc.spec.ports}
    port_a, port_b = ports.get("jupyter"), ports.get("app")
    if svc.spec.type == "LoadBalancer":
        ing = (svc.status.load_balancer and svc.status.load_balancer.ingress) or []
        host_or_ip = (ing[0].ip or ing[0].hostname) if ing else None
        ext_a = port_a.port if port_a else None
        ext_b = port_b.port if port_b else None
        return host_or_ip, ext_a, ext_b
    else:  # NodePort
        node_ip = get_node_external_ip()
        ext_a = port_a.node_port if port_a else None
        ext_b = port_b.node_port if port_b else None
        return node_ip, ext_a, ext_b

def wait_for_service_external_ready(svc_name: str, timeout: int = WAIT_TIMEOUT) -> Tuple[Optional[str], Optional[int], Optional[int]]:
    """Wait until service has an externally reachable address/ports."""
    start = time.time()
    while time.time() - start < timeout:
        svc = core.read_namespaced_service(name=svc_name, namespace=NAMESPACE)
        host, a, b = external_access_for_service(svc)
        if svc.spec.type == "LoadBalancer":
            if host and a and b:
                return host, a, b
        else:  # NodePort
            if host and a and b:
                return host, a, b
        time.sleep(2)
    return None, None, None

def create_pod_and_service(email: str, wait_ready: bool = True) -> Tuple[str, str, Optional[str], Optional[int], Optional[int]]:
    """
    Create a Pod + Service for the given email.
    Follows your spec: pip install jupyter/ihighlight, tolerations, hostPath volume,
    env vars, GPU resources, security context, restartPolicy=Never, allow-root.
    """
    pod_name, svc_name = name_for_email(email)
    owner = sanitize_name(email, 30)

    labels = {
        APP_LABEL_KEY: APP_LABEL_VAL,
        OWNER_LABEL_KEY: owner,
    }
    annotations = {
        EMAIL_ANNOTATION_KEY: email
    }

    # Container command
    cmd = [
        "bash", "-lc",
        "pip install --no-cache-dir jupyter ihighlight && "
        f"cd /app && jupyter lab --ServerApp.token='' --ServerApp.password='' "
        f"--ServerApp.allow_origin='*' --ip=0.0.0.0 --port={CONTAINER_PORT_A} "
        f"--no-browser --allow-root --ServerApp.trust_xheaders=True"
    ]

    # Volumes & mounts
    volumes = [
        client.V1Volume(
            name="models-volume",
            host_path=client.V1HostPathVolumeSource(path="/mnt/models")
        )
    ]
    volume_mounts = [
        client.V1VolumeMount(
            name="models-volume",
            mount_path="/models"
        )
    ]

    # Environment
    envs = [
        client.V1EnvVar(name="SHELL", value="/bin/bash"),
        client.V1EnvVar(name="EXA_API_KEY", value=EXA_API_KEY),
    ]

    # Resources (GPU via amd.com/gpu)
    resources = client.V1ResourceRequirements(
        limits={"amd.com/gpu": "1"},
        requests={"amd.com/gpu": "1"},
    )

    container = V1Container(
        name="nb",
        image=NOTEBOOK_IMAGE,
        command=cmd,
        ports=[
            V1ContainerPort(container_port=CONTAINER_PORT_A, name="jupyter"),
            V1ContainerPort(container_port=CONTAINER_PORT_B, name="app"),
        ],
        env=envs,
        volume_mounts=volume_mounts,
        resources=resources,
        security_context=V1SecurityContext(
            run_as_user=0,
            capabilities=client.V1Capabilities(add=["SYS_PTRACE"]),
            privileged=False,
        ),
    )

    pod = V1Pod(
        metadata=V1ObjectMeta(
            name=pod_name,
            namespace=NAMESPACE,
            labels=labels,
            annotations=annotations,
        ),
        spec=V1PodSpec(
            tolerations=[
                client.V1Toleration(
                    key="amd.com/gpu",
                    operator="Exists",
                    effect="NoSchedule",
                )
            ],
            restart_policy="Never",
            volumes=volumes,
            containers=[container],
        )
    )

    # Create Pod
    try:
        core.create_namespaced_pod(namespace=NAMESPACE, body=pod)
    except ApiException as e:
        if e.status != 409:
            raise

    # Service with optional NodePort assignment
    node_port_a = NODE_PORT_A if (SERVICE_TYPE == "NodePort" and NODE_PORT_A) else None
    node_port_b = NODE_PORT_B if (SERVICE_TYPE == "NodePort" and NODE_PORT_B) else None

    svc_ports = [
        V1ServicePort(
            name="jupyter",
            port=SERVICE_PORT_A,
            target_port=CONTAINER_PORT_A,
            node_port=node_port_a
        ),
        V1ServicePort(
            name="app",
            port=SERVICE_PORT_B,
            target_port=CONTAINER_PORT_B,
            node_port=node_port_b
        ),
    ]

    svc = V1Service(
        metadata=V1ObjectMeta(
            name=svc_name,
            namespace=NAMESPACE,
            labels=labels,
            annotations=annotations,
        ),
        spec=V1ServiceSpec(
            type=SERVICE_TYPE,
            selector=labels,
            ports=svc_ports
        )
    )

    try:
        core.create_namespaced_service(namespace=NAMESPACE, body=svc)
    except ApiException as e:
        if e.status == 409:
            pass
        elif e.status == 422 and SERVICE_TYPE == "NodePort":
            # Fallback: let API server auto-assign nodePort to avoid "port already allocated"
            for p in svc.spec.ports:
                p.node_port = None
            core.create_namespaced_service(namespace=NAMESPACE, body=svc)
        else:
            raise

    if not wait_ready:
        return pod_name, svc_name, None, None, None

    host, ext_a, ext_b = wait_for_service_external_ready(svc.metadata.name, WAIT_TIMEOUT)
    return pod_name, svc_name, host, ext_a, ext_b

# -----------------------------
# Response models
# -----------------------------
class TaskResponse(BaseModel):
    email: str
    jupyter_url: Optional[str] = None
    app_url_hint: Optional[str] = None
    status_url: Optional[str] = None
    k8s: Dict

class StatusResponse(BaseModel):
    email: str
    state: str                 # NOT_FOUND | CREATING | READY | ERROR
    progress: int              # 0~100
    details: Dict
    jupyter_url: Optional[str] = None
    app_url: Optional[str] = None

# -----------------------------
# UI: Home (Login + Progress page, EN)
# -----------------------------
@app.get("/", response_class=HTMLResponse)
def index():
    return """
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Video Task Launcher</title>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <style>
    :root { color-scheme: light dark; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial; margin: 24px; }
    .card { max-width: 720px; margin: 0 auto; padding: 20px; border: 1px solid #e5e7eb; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,.06); }
    h2 { margin: 0 0 12px 0; }
    label { display: block; margin: 10px 0 6px; color: #374151; }
    input[type="text"] { width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 8px; }
    button { margin-top: 12px; padding: 10px 16px; border: 0; background: #2563eb; color: #fff; border-radius: 8px; cursor: pointer; }
    button:disabled { opacity: .6; cursor: not-allowed; }
    .bar { width: 100%; height: 16px; border: 1px solid #9ca3af; border-radius: 8px; overflow: hidden; background: #f3f4f6; }
    .fill { height: 100%; width: 0%; background: linear-gradient(90deg, #22c55e, #16a34a); transition: width .4s; }
    .hint { color: #6b7280; font-size: 13px; }
    .error { color: #dc2626; margin-top: 8px; }
    .links a { margin-right: 12px; }
    code { background: #f6f8fa; padding: 2px 6px; border-radius: 4px; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Launch / Open Your Notebook</h2>
    <p class="hint">
      Enter your corporate email and click <b>Launch</b>. We will create (or reuse) a dedicated Notebook Pod and a Service with two ports:
      <br/>• Port A → JupyterLab (default <code>8888</code>) &nbsp; • Port B → Your app (default <code>9000</code>)
    </p>

    <label>Email</label>
    <input id="email" type="text" placeholder="alice@example.com"/>
    <button id="launch">Launch</button>
    <div id="err" class="error"></div>

    <h3 style="margin-top:20px;">Progress</h3>
    <div class="bar"><div class="fill" id="fill"></div></div>
    <p>Status: <span id="state">-</span> (<span id="progress">0</span>%)</p>

    <p class="hint">
      Once Jupyter is up, open the Terminal and start your service on <code>9000</code>
      (e.g., <code>python -m http.server 9000</code> or <code>uvicorn app:app --host 0.0.0.0 --port 9000</code>).
      Then use the "Your App" link above.
    </p>
  </div>

<script>
(function () {
  let timer = null;
  const $ = (id) => document.getElementById(id);

  // 如果缺少容器/链接，则自动创建，避免 "not found"
  function ensureContainer() {
    let container = $('links');
    if (!container) {
      container = document.createElement('div');
      container.className = 'links';
      container.id = 'links';
      // 安放到页面合适位置：优先进度条后面
      const after = document.querySelector('.bar')?.parentElement || document.body;
      after.appendChild(container);
    }
    return container;
  }
  function ensureLink(id, label) {
    let a = $(id);
    if (!a) {
      const container = ensureContainer();
      const p = document.createElement('p');
      p.appendChild(document.createTextNode(label + ': '));
      a = document.createElement('a');
      a.id = id;
      a.href = '#';
      a.target = '_blank';
      p.appendChild(a);
      container.appendChild(p);
    }
    return a;
  }

  function setBusy(b) { 
    const btn = $('launch'), inp = $('email');
    if (btn) btn.disabled = b;
    if (inp) inp.disabled = b;
  }
  function setErr(msg) {
    const el = $('err');
    if (el) el.textContent = msg || '';
  }
  function setText(id, text) {
    const el = $(id);
    if (el) el.textContent = text ?? '';
  }
  function setWidth(id, w) {
    const el = $(id);
    if (el) el.style.width = w;
  }

  // 兜底生成链接：优先用 jupyter_url/app_url；否则用 host+ports
  function deriveLinks(data) {
    let j = data?.jupyter_url || '';
    let a = data?.app_url || '';
    const host = data?.details?.service?.host;
    const ports = data?.details?.service?.ports || {};
    if (!j && host && ports.jupyter) j = `http://${host}:${ports.jupyter}`;
    if (!a && host && ports.app)     a = `http://${host}:${ports.app}`;
    return { j, a };
  }

  function setUI(data) {
    setText('state', data?.state || '-');
    const p = Math.max(0, Math.min(100, data?.progress ?? 0));
    setText('progress', String(p));
    setWidth('fill', p + '%');

    const { j, a } = deriveLinks(data);
    const jEl = ensureLink('jurl', 'Jupyter');
    const aEl = ensureLink('aurl', 'Your App');
    jEl.href = j || '#';
    jEl.textContent = j || '';
    aEl.href = a || '#';
    aEl.textContent = a || '';
  }

  async function startAsync(email) {
    setBusy(true); setErr('');
    try {
      const res = await fetch(`/video_task?email=${encodeURIComponent(email)}&async=1`);
      if (!res.ok) {
        setErr('Launch failed: ' + (await res.text()));
        return;
      }
      poll(email);
    } catch (e) {
      setErr('Launch exception: ' + e);
    } finally {
      setBusy(false);
    }
  }

  async function poll(email) {
    if (timer) clearTimeout(timer);
    try {
      // 加时间戳防缓存
      const url = `/status?email=${encodeURIComponent(email)}&_=${Date.now()}`;
      const res = await fetch(url, { cache: 'no-store' });
      if (!res.ok) {
        setErr(`Status error: ${res.status} ${await res.text()}`);
        return;
      }
      const data = await res.json();
      setUI(data);

      if (data.state !== 'READY') {
        timer = setTimeout(() => poll(email), 2000);
      } else {
        setErr('');
      }
    } catch (e) {
      setErr('Status exception: ' + e);
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    const btn = $('launch'), emailInput = $('email');
    if (btn && emailInput) {
      btn.onclick = () => {
        const email = (emailInput.value || '').trim();
        if (!email) return setErr('Please enter your email.');
        localStorage.setItem('video_email', email);
        startAsync(email);
      };
      emailInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') btn.click();
      });
    }

    // Prefill & auto-launch if ?email= provided
    const params = new URLSearchParams(location.search);
    const pEmail = params.get('email');
    const saved = localStorage.getItem('video_email');
    if (emailInput) emailInput.value = pEmail || saved || '';
    if (pEmail) startAsync(pEmail);
  });
})();
</script>
</body>
</html>
    """

# -----------------------------
# API: Create / Reuse task
# -----------------------------
@app.get("/video_task", response_model=TaskResponse)
def video_task(
    email: str = Query(..., description="User email"),
    async_mode: bool = Query(False, alias="async", description="true=async; client polls /status")
):
    if email.lower() == "all":
        raise HTTPException(status_code=400, detail="email=all is only allowed for cleanup")

    check_email_allowed(email)

    svc = find_existing_service(email)
    if svc:
        host, a, b = external_access_for_service(svc)
        jupyter_url = f"http://{host}:{a}" if (host and a) else None
        app_url = f"http://{host}:{b}" if (host and b) else None

        return TaskResponse(
            email=email,
            jupyter_url=jupyter_url,
            app_url_hint=app_url or "(Not ready yet: start your app on 9000 inside Jupyter Terminal)",
            status_url=f"/status?email={email}",
            k8s={
                "namespace": NAMESPACE,
                "service_name": svc.metadata.name,
                "service_type": svc.spec.type,
                "ports": {"jupyter": a, "app": b},
            }
        )

    if async_mode:
        create_pod_and_service(email, wait_ready=False)
        return TaskResponse(
            email=email,
            jupyter_url=None,
            app_url_hint="Creating... please poll /status",
            status_url=f"/status?email={email}",
            k8s={"namespace": NAMESPACE}
        )
    else:
        _, svc_name, host, a, b = create_pod_and_service(email, wait_ready=True)
        return TaskResponse(
            email=email,
            jupyter_url=f"http://{host}:{a}",
            app_url_hint=f"http://{host}:{b}  (Start your app on {CONTAINER_PORT_B} inside Jupyter Terminal)",
            status_url=f"/status?email={email}",
            k8s={
                "namespace": NAMESPACE,
                "service_name": svc_name,
                "service_type": SERVICE_TYPE,
                "ports": {"jupyter": a, "app": b},
            }
        )

# -----------------------------
# API: Status (for polling)
# -----------------------------
@app.get("/status", response_model=StatusResponse)
def status(email: str = Query(..., description="User email")):
    if email.lower() == "all":
        raise HTTPException(status_code=400, detail="email=all is not supported for status")

    check_email_allowed(email)

    pod = find_existing_pod(email)
    svc = find_existing_service(email)

    if not pod and not svc:
        return StatusResponse(
            email=email,
            state="NOT_FOUND",
            progress=0,
            details={"message": "No resources found"}
        )

    progress = 10
    details: Dict = {}

    if pod:
        phase = pod.status.phase or "Unknown"
        ready_cond = False
        if pod.status.conditions:
            ready_cond = any(c.type == "Ready" and c.status == "True" for c in pod.status.conditions)
        details["pod"] = {"name": pod.metadata.name, "phase": phase, "ready": ready_cond}
        if phase in ("Pending", "Unknown"):
            progress = max(progress, 30)
        elif phase == "Running":
            progress = max(progress, 60)
        elif phase in ("Succeeded", "Failed"):
            progress = max(progress, 60)
    else:
        details["pod"] = {"message": "Pod not created yet"}

    host, a, b = None, None, None
    if svc:
        host, a, b = external_access_for_service(svc)
        details["service"] = {
            "name": svc.metadata.name,
            "type": svc.spec.type,
            "host": host,
            "ports": {"jupyter": a, "app": b}
        }
        if (svc.spec.type == "LoadBalancer" and host) or (svc.spec.type == "NodePort" and host and a and b):
            progress = max(progress, 80)
    else:
        details["service"] = {"message": "Service not created yet"}

    jupyter_url = f"http://{host}:{a}" if (host and a) else None
    app_url = f"http://{host}:{b}" if (host and b) else None

    if pod and pod.status.phase == "Running" and jupyter_url:
        state = "READY"
        progress = 100
    elif pod and pod.status.phase in ("Failed",):
        state = "ERROR"
    else:
        state = "CREATING"

    return StatusResponse(
        email=email,
        state=state,
        progress=min(progress, 100),
        details=details,
        jupyter_url=jupyter_url,
        app_url=app_url
    )

# -----------------------------
# API: Cleanup (admin only; not on UI)
# -----------------------------
@app.delete("/video_task")
def cleanup(
    email: str = Query(..., description="Email to clean; use 'all' to delete all resources"),
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    require_admin(x_admin_token)

    if email.lower() == "all":
        label_selector = f"{APP_LABEL_KEY}={APP_LABEL_VAL}"
        svcs = core.list_namespaced_service(namespace=NAMESPACE, label_selector=label_selector).items
        pods = core.list_namespaced_pod(namespace=NAMESPACE, label_selector=label_selector).items

        deleted = {"services": [], "pods": []}
        for s in svcs:
            try:
                core.delete_namespaced_service(name=s.metadata.name, namespace=NAMESPACE)
                deleted["services"].append(s.metadata.name)
            except ApiException as e:
                if e.status != 404:
                    raise
        for p in pods:
            try:
                core.delete_namespaced_pod(name=p.metadata.name, namespace=NAMESPACE)
                deleted["pods"].append(p.metadata.name)
            except ApiException as e:
                if e.status != 404:
                    raise
        return {"ok": True, "deleted": deleted}

    check_email_allowed(email, for_cleanup=True)
    pod = find_existing_pod(email)
    svc = find_existing_service(email)

    deleted = {"services": [], "pods": []}
    if svc:
        try:
            core.delete_namespaced_service(name=svc.metadata.name, namespace=NAMESPACE)
            deleted["services"].append(svc.metadata.name)
        except ApiException as e:
            if e.status != 404:
                raise
    if pod:
        try:
            core.delete_namespaced_pod(name=pod.metadata.name, namespace=NAMESPACE)
            deleted["pods"].append(pod.metadata.name)
        except ApiException as e:
            if e.status != 404:
                raise

    return {"ok": True, "deleted": deleted}

# -----------------------------
# Health
# -----------------------------
@app.get("/healthz")
def healthz():
    return {"ok": True}
