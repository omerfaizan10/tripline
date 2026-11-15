# Sandbox image: the agent runs here as an unprivileged user.
# strace records what it does; blast-shim (mounted at run time) confines it.
FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      strace git ca-certificates curl python3 python3-pip python3-venv ripgrep \
 && rm -rf /var/lib/apt/lists/*

# Python environment for benchmark tasks (Django 4.1 to 5.0 run from source).
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir asgiref==3.8.1 sqlparse==0.5.1 tzdata==2024.2 \
 # Optional test dependencies from Django's tests/requirements/py3.txt, as the
 # SWE-bench harness installs them; without them tests are skipped and graded
 # as not passing. Left out: pylibmc and pywatchman (need system libraries)
 # and black (reformats makemigrations output).
 && /opt/venv/bin/pip install --no-cache-dir \
      Jinja2==3.1.4 Pillow==10.4.0 PyYAML==6.0.2 numpy==1.26.4 argon2-cffi==23.1.0 \
      bcrypt==4.2.0 docutils==0.21.2 tblib==3.0.0 pymemcache==4.0.0 redis==5.0.8 \
      geoip2==4.8.0 selenium==4.25.0 aiosmtpd==1.4.6 \
 && chmod -R a+rX /opt/venv
ENV PATH=/opt/venv/bin:$PATH

# Agents under test, pinned.
RUN npm install -g @openai/codex@0.165.0 && npm cache clean --force

# The node image already has uid 1000 ("node"); rename it to "agent".
RUN usermod -l agent -d /home/agent -m node && groupmod -n agent node \
 && mkdir -p /work /blast && chown agent:agent /work

ENV HOME=/home/agent
USER agent
WORKDIR /work
