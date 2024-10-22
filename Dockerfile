FROM alpine:3.20 AS cpp-buildenv

WORKDIR /tmp

RUN apk update --no-cache && \
    apk add --no-cache ca-certificates \
    samurai git openssl-dev openssl pkgconf cmake \
    clang18 clang18-extra-tools && \
    git clone https://github.com/OpenBrickProtocolFoundation/simulator simulator

ENV CC=clang-18
ENV CXX=clang++-18
ENV LD=clang-18

WORKDIR /tmp/simulator/

RUN cmake -B build -G "Ninja" \
    -DCMAKE_BUILD_TYPE=Release \
    -Dobpf_build_tests=OFF \
    -Dobpf_simulator_enable_undefined_behavior_sanitizer=OFF \
    -Dobpf_simulator_enable_address_sanitizer=OFF \
    -Dobpf_simulator_warnings_as_errors=ON \
    -Dobpf_simulator_build_shared_libs=OFF && \
    cmake --build build



# final image starts here

FROM python:3.12-alpine

WORKDIR /app


# install python dependencies

COPY requirements.txt requirements.txt

RUN pip3 install --no-cache-dir -r requirements.txt

COPY lobby/ lobby/

# copy game server

ENV OBBF_CONFIG_PATH=/app/config/config.json
ENV OBBF_GAMESERVER_EXECUTABLE=/app/gameserver/server
ENV OBBF_SIMULATOR_LIBRARY_PATH=/app/gameserver/
ENV OBPF_IS_DOCKER=true

ENV PYTHONPATH="${PYTHONPATH}:/app/"

COPY --from=cpp-buildenv /tmp/simulator/build/bin/server/server /app/gameserver/

## add finalization arguments

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD curl -f -X GET http://localhost:1717/health

EXPOSE 1717

CMD [ "python3", "lobby/main.py", "production"]
