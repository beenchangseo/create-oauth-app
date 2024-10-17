# 빌드 단계
FROM node:20-bullseye AS builder

ENV GOSU_VERSION=1.10 \
    TINI_VERSION=v0.19.0 \
    GOSU_KEY=B42F6819007F00F88E364FD4036A9C25BF357DD4 \
    TINI_KEY=595E85A6B1B4779EA4DAAEC70B588DFF0527A9B7

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        gnupg \
        dirmngr \
        wget \
        neovim \
        libcairo2-dev \
        libjpeg-dev \
        libpango1.0-dev \
        libgif-dev \
        build-essential \
        g++; \
    \
    # GNUPGHOME 설정
    export GNUPGHOME="$(mktemp -d)"; \
    \
    # gosu 설치
    dpkgArch="$(dpkg --print-architecture | awk -F- '{ print $NF }')"; \
    wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch"; \
    wget -O /usr/local/bin/gosu.asc "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch.asc"; \
    gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$GOSU_KEY"; \
    gpg --batch --verify /usr/local/bin/gosu.asc /usr/local/bin/gosu; \
    chmod +x /usr/local/bin/gosu; \
    gosu nobody true; \
    \
    # tini 설치
    wget -O /usr/local/bin/tini "https://github.com/krallin/tini/releases/download/$TINI_VERSION/tini"; \
    wget -O /usr/local/bin/tini.asc "https://github.com/krallin/tini/releases/download/$TINI_VERSION/tini.asc"; \
    gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$TINI_KEY"; \
    gpg --batch --verify /usr/local/bin/tini.asc /usr/local/bin/tini; \
    chmod +x /usr/local/bin/tini; \
    \
    # 정리
    rm -rf "$GNUPGHOME" /usr/local/bin/gosu.asc /usr/local/bin/tini.asc; \
    apt-get purge -y --auto-remove gnupg dirmngr wget; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

# 의존성 설치
WORKDIR /opt/create-oauth-app/
COPY package*.json ./
RUN npm install

# 소스 코드 복사
COPY . /opt/create-oauth-app/

# 빌드 실행
RUN npm run build

# 런타임 단계
FROM node:20-alpine

# 필요한 패키지 설치
RUN apk add --no-cache ca-certificates

# 사용자 생성
RUN addgroup -S beenslab && adduser -S beenslab -G beenslab

# 실행 파일 복사
COPY --from=builder /usr/local/bin/gosu /usr/local/bin/tini /usr/local/bin/
COPY --from=builder /opt/create-oauth-app /opt/create-oauth-app

# 권한 설정
RUN chown -R beenslab:beenslab /opt/create-oauth-app

USER beenslab

ENTRYPOINT ["/usr/local/bin/tini", "--", "/opt/create-oauth-app/src/scripts/docker-entrypoint.sh"]
CMD ["create-oauth-app", "create-oauth-app"]
