# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM python:3.14.7-slim-trixie@sha256:51dafde81dbdb6ebde285137a295cf18a47ca95234fe388a343719cb97305b3d
WORKDIR /opt/server-ai-project-reader
COPY --chown=0:0 --chmod=0444 server-ai/scripts/common.py /usr/local/lib/python3.14/site-packages/server_ai_reader_common.py
COPY --chown=0:0 --chmod=0555 server-ai/scripts/source_reader.py ./source_reader.py
USER 1000:1000
EXPOSE 8110
ENTRYPOINT ["python3", "-I", "/opt/server-ai-project-reader/source_reader.py"]
