FROM python:3.12-slim

# Core CLI only (no Streamlit / Groq). Evidence is mounted at /data.
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && rm -rf /app

# Run as an unprivileged user: evidence is untrusted input.
RUN useradd --create-home --uid 10001 triage
USER triage
WORKDIR /data

ENTRYPOINT ["dfir-triage"]
CMD ["--help"]
