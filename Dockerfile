FROM python:3.12-slim
WORKDIR /app
COPY . .
EXPOSE 2222 8080
ENV PN_LOG_DIR=/data
VOLUME /data
CMD ["python", "-m", "phantomnet", "run"]
