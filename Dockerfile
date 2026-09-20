# SIH26228 — production image for the analyst platform (Module 5).
#
# The application is a read-only console over the assurance engine's output: it
# computes nothing at request time and reads JSON reports from disk. So the
# computer vision runs HERE, in stage 1, at image build time. Modules 1-4
# execute for real over the attack labs — perceptual and classical feature
# extraction, near-duplicate and OOD detection, ONNX activation probing,
# TorchScript gradient-based trigger reconstruction, Ed25519 provenance chain
# verification, population shift characterisation — and their reports become
# the feed the runtime serves. Nothing is stubbed and nothing degrades
# silently: the build fails if any of the 19 pipeline scenarios cannot run for
# want of a runtime or a lab.
#
# Stage 3 carries only Node and those reports. There is no Python, no torch and
# no imagery in the served image, and no network call at run time.

# ---------------------------------------------------------------------------
# 1. engine — Python 3.13, the real Modules 1-4, and the analyst feed
# ---------------------------------------------------------------------------
FROM python:3.13-slim-bookworm AS engine

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# libgomp1 is the OpenMP runtime torch, scipy and onnxruntime link against;
# python:slim does not ship it. Nothing else is needed: every dependency has a
# manylinux wheel, so this image carries no compiler.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libgomp1 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# CPU-only torch, from PyTorch's own index. The default PyPI wheel for Linux
# carries the CUDA toolkit (~2.5 GB) and this deployment has no GPU. The
# gradient pathway trigger reconstruction needs works identically on CPU; it is
# slower, which costs build time, never request time.
RUN pip install --index-url https://download.pytorch.org/whl/cpu "torch>=2.2"

# Everything else from PyPI. torch is already satisfied, so it is not replaced
# by the CUDA build.
COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-deps .

COPY configs ./configs
COPY scripts ./scripts

# The Module 4 population lab is version-controlled. The other three labs are
# generated below, as pure functions of their published seeds.
COPY assurance_lab ./assurance_lab

# The lab scripts default to ./.venv/bin/cvtrust; here the console script is on
# PATH because the interpreter is the image's own.
ENV CVTRUST=cvtrust

# Module 1 (~50 s): the clean corpus, all six dataset attack scenarios, and the
# measured calibration table the policy engine requires before it may recommend
# quarantine on a threshold-based finding.
RUN mkdir -p reports && ./scripts/evaluate.sh

# Module 3 (~10 s): 28 provenance scenarios, signed with Ed25519.
RUN ./scripts/provenance-evaluate.sh

# Module 2 (~70 s): trains the reference network and 15 scenario models, and
# exports each as both ONNX and TorchScript.
RUN cvtrust -q lab model-build --out model_lab

# Module 5 (~40 s): run the real Module 1-4 pipelines over all 19 pipeline
# scenarios and write the feed. Export status 1 means the feed was written but
# some scenario had no upstream lab; verify-analyst-feed.py is what refuses to
# ship that.
RUN cvtrust analyst export --out /feed || [ $? -le 1 ] \
 && python scripts/verify-analyst-feed.py /feed

# ---------------------------------------------------------------------------
# 2. web — build the analyst platform against the feed the engine just wrote
# ---------------------------------------------------------------------------
FROM node:22-slim AS web

ENV NEXT_TELEMETRY_DISABLED=1
# Emit .next/standalone: the same compiled application with only the traced
# closure of node_modules beside it. Off by default in next.config.mjs so that
# `next start`, run.sh and scripts/module5-verify.sh keep working locally.
ENV NEXT_OUTPUT_STANDALONE=1
WORKDIR /app/web

# .npmrc carries legacy-peer-deps: @react-three/fiber declares a peer range of
# react <19.3 and this application is built and verified against 19.3.
COPY web/package.json web/package-lock.json web/.npmrc ./
RUN npm ci --legacy-peer-deps --no-audit --no-fund

COPY web/ ./
COPY --from=engine /feed /app/reports/analyst

# web/.env is Git-ignored and written from its template by setup.sh; do the same
# here so the build behaves exactly as a developer's does. Then the two gates
# the project asks for before a commit: the projection tests, and a build that
# fails on a type error.
RUN cp .env.example .env && npm test && npm run build

# ---------------------------------------------------------------------------
# 3. runtime — Node and the reports, nothing else
# ---------------------------------------------------------------------------
FROM node:22-slim AS runtime

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# Next's standalone server reads both. Binding to 0.0.0.0 rather than localhost
# is what makes the service reachable from outside the container.
ENV HOSTNAME=0.0.0.0
ENV PORT=10000

# Absolute, so the data layer never depends on the process's working directory.
ENV CVTRUST_DEMO_DIR=/app/reports/analyst
ENV CVTRUST_LIVE_DIR=/app/reports/live

WORKDIR /app/web

# The traced server bundle, then the two things tracing does not cover.
COPY --from=web /app/web/.next/standalone ./
COPY --from=web /app/web/.next/static ./.next/static
COPY --from=web /app/web/public ./public

# The engine's output, byte for byte as it wrote it.
COPY --from=engine /feed /app/reports/analyst

# LIVE stays empty. A real assessment is published here by an operator, and
# until one is, the platform must say "no live assessment" rather than show
# laboratory data in its place.
RUN mkdir -p /app/reports/live && chown -R node:node /app/reports/live

USER node
EXPOSE 10000

CMD ["node", "server.js"]
