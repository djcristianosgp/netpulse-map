# Stage 1: Build native C++20 binary for Linux
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY src/ ./src/
COPY third_party/ ./third_party/

RUN mkdir -p /out && \
    gcc -O2 -DSQLITE_THREADSAFE=1 -c third_party/sqlite/sqlite3.c -o /out/sqlite3.o && \
    g++ -std=c++20 -O2 -Wall -Wextra -pthread -Isrc -Ithird_party/sqlite \
      -DNETPULSE_VERSION=\"1.10.0\" \
      src/main.cpp \
      src/core/json_lite.cpp \
      src/security/auth_manager.cpp \
      src/security/audit_log.cpp \
      src/security/rate_limiter.cpp \
      src/security/tls_context.cpp \
      src/storage/sqlite_db.cpp \
      src/api/api_router.cpp \
      src/net_monitor.cpp \
      src/geo_dns.cpp \
      src/ws_server.cpp \
      src/updater.cpp \
      src/service_monitor.cpp \
      src/settings_store.cpp \
      src/mmdb_reader.cpp \
      src/traceroute.cpp \
      src/history_store.cpp \
      src/quality/network_quality_engine.cpp \
      src/network/interface_monitor.cpp \
      src/discovery/discovery_engine.cpp \
      src/discovery/topology_builder.cpp \
      src/intelligence/intelligence_engine.cpp \
      src/actions.cpp \
      src/tray_host.cpp \
      /out/sqlite3.o \
      -o /out/netpulse \
      -lssl -lcrypto -ldl

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    traceroute \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /out/netpulse /app/netpulse
COPY static/ /app/static/
COPY assets/ /app/assets/
RUN mkdir -p /app/data

EXPOSE 8740

ENTRYPOINT ["/app/netpulse"]
CMD ["--no-browser", "--host", "0.0.0.0", "--allow-remote", "--port", "8740"]
