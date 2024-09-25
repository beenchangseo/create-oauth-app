# OAuth 2.0 Starter Kit

이 프로젝트는 OAuth 2.0 인증 서버를 NestJS로 구현한 스타터 키트입니다. 세션 기반 인증 방식을 사용하며, 세션 관리에는 Redis를, 데이터베이스 관리에는 PostgreSQL과 Prisma ORM을 사용합니다.

## 기능

-   OAuth 2.0 인증 프로토콜 구현
-   세션 기반 사용자 인증
-   Redis를 사용한 세션 스토리지
-   PostgreSQL 데이터베이스 사용
-   Prisma ORM을 통한 데이터베이스 관리

## 시작하기

### 필요 조건

-   Node.js (버전 20.9.0)
-   PostgreSQL
-   Redis

### 설치

1. 레포지토리를 클론합니다.

```bash
git clone https://your-repository-url-here.git
cd your-project-directory
```

2. 필요한 npm 패키지를 설치합니다.

```bash
npm install
```

3. .env 파일을 생성하고 필요한 환경 변수를 설정합니다.

```makefile
# Environment variables declared in this file are automatically made available to Prisma.
# See the documentation for more detail: https://pris.ly/d/prisma-schema#accessing-environment-variables-from-the-schema

# Prisma supports the native connection string format for PostgreSQL, MySQL, SQLite, SQL Server, MongoDB and CockroachDB.
# See the documentation for all the connection string options: https://pris.ly/d/connection-strings

DATABASE_URL=postgresql://localhost:password@localhost:5432/test-db?schema=public

REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

SESSION_SECRET=session_secret

PASSWORD_SALT=password_salt

```

### 사용법
프로젝트를 로컬에서 실행하려면 다음 명령어를 사용합니다.
```bash
npm run start:dev
```

### API 참조
WIP

### 기여하기
이 스타터 키트는 오픈 소스 프로젝트입니다. 기여를 원하시는 분은 이슈를 등록하거나 풀 리퀘스트를 보내주세요.

### 라이선스
이 프로젝트는 MIT 라이선스를 따릅니다. package.json 파일을 참조해주세요.