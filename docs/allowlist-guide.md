# allowlist.yaml 작성 가이드

`.ssh_harness/allowlist.yaml` 한 파일이 ssh-harness의 보안 계약(security contract) 입니다. 이 파일에 정의된 룰(rule) 하나가 LLM에 노출되는 MCP 툴 하나가 되고, 그 안의 `params`/`template`이 LLM이 입력할 수 있는 값과 실제로 실행될 argv를 모두 결정합니다. 코드 변경 없이 YAML 편집만으로 진단 명령을 추가/제거할 수 있는 대신, 잘못 쓰면 host에 그대로 노출됩니다.

이 가이드는 **무엇을 쓸 수 있는지 / 무엇이 reject되는지 / 어떤 패턴이 안전한지**를 케이스별로 정리합니다.

---

## 1. 파일 구조 개요

```yaml
version: 2                     # 반드시 2 (literal)

hosts:                         # 객체. allowHosts는 필수, sshConfigRoot는 옵션.
  allowHosts: &hosts ["host-a"]   # ssh_config Host 별칭 리스트. 비어있으면 reject
  sshConfigRoot: "./ssh_config"   # 옵션. 미작성 시 ~/.ssh/config로 default

settings:                      # 옵션. 모두 default 있음
  timeoutMs: 30000
  maxStdoutBytes: 262144
  maxStderrBytes: 65536
  sshBin: /usr/bin/ssh
  identityFile: ~/.ssh/id_ed25519   # 옵션. 없으면 sshConfigRoot의 IdentityFile 사용

rules:                         # 룰 배열. cap=40 (SSH_HARNESS_MAX_RULES로 조절)
  - id: get_uptime
    tool:
      name: ssh_harness_get_uptime     # /^[a-z][a-z0-9_]{0,63}$/
      description: |
        LLM에 노출되는 멀티라인 설명. 무엇을 하는지 + 언제 써야 하는지.
    params:
      host:
        type: string
        enum: *hosts
    template:
      host: "{host}"
      argv: [uptime]
```

탑 레벨 키 4개(`version`, `hosts`, `settings`, `rules`) 외의 키는 Zod loader가 무시합니다. 단 룰 객체와 param 스펙은 `.strict()`가 아니므로 오타에 주의하세요 (placeholder lint가 잡지만, `maxiimum` 같은 오타는 silently 무시됩니다).

---

## 2. 탑 레벨 필드

### `version: 2`
- literal `2`만 허용. 미래 스키마 변경 시 bumped.

### `hosts`
객체. 두 필드:

#### `hosts.allowHosts` (필수)
- 비어있지 않은 string 배열. 각 항목은 resolved ssh_config의 `Host <alias>` 선언과 일치해야 함.
- 매칭 실패 시 startup 시점에 strictLint=on이면 `exit 3`, off면 `[WARN]`.
- **YAML anchor 패턴 권장**: `allowHosts: &hosts ["api-prod", "api-stage"]` → 룰에서 `enum: *hosts`로 재사용.

#### `hosts.sshConfigRoot` (옵션)
- OpenSSH client config 파일 경로. 룰을 실행할 때 `ssh -F <이 경로>`로 전달됨.
- **상대 경로**는 allowlist.yaml 파일의 디렉토리 기준으로 해소됩니다 (`./ssh_config` → 같은 디렉토리의 `ssh_config`).
- **`~/`** prefix는 user home으로 expand (`~/.ssh/config` → `/home/user/.ssh/config`).
- 절대 경로도 그대로 사용 가능.
- **미작성 시 default = `~/.ssh/config`**.

#### ssh_config 경로 해소 우선순위
1. `SSH_HARNESS_CONFIG` env (test/operator override)
2. `hosts.sshConfigRoot` (이 파일에 지정)
3. `~/.ssh/config`

이 우선순위 때문에 단위 테스트에서는 env로 override 가능하면서, 평소엔 allowlist가 single source of truth입니다.

> **신뢰 가정 (alias → endpoint):** allowlist는 host **별칭(alias) 이름**만 강제합니다. 실제 접속 대상(`HostName`/`ProxyJump` 등)은 ssh가 실행 시점에 resolved ssh_config에서 읽습니다. 즉 별칭이 가리키는 endpoint를 바꾸면(파일 수정) allowlist 우회 없이 다른 호스트로 접속될 수 있습니다(TOCTOU). **resolved ssh_config 파일은 allowlist.yaml과 동일한 수준으로 보호하세요** (CODEOWNERS / 파일 권한). 별칭은 startup 시 1회 스냅샷됩니다.

### `settings`
| 키 | 기본값 | 용도 |
|---|---|---|
| `timeoutMs` | 30000 | spawnSync 타임아웃. 초과 시 SIGTERM → `outcome=timeout` |
| `maxStdoutBytes` | 262144 (256 KiB) | stdout 캡. 초과분은 UTF-8 codepoint 경계에서 잘리고 `truncated:true`. **`0`이면 캡 해제 (무제한)** — spawnSync `maxBuffer`도 `Infinity`로 승격. |
| `maxStderrBytes` | 65536 (64 KiB) | stderr 캡. **`0`이면 캡 해제 (무제한)** |
| `sshBin` | `/usr/bin/ssh` | OpenSSH client 절대경로 |
| `identityFile` | (unset) | 명시 시 `-i <path>` 추가. unset이면 resolved ssh_config의 `IdentityFile` 사용 |

룰 단위 override는 없습니다. **single source of truth**가 원칙.

### `rules`
- cap=40 (env `SSH_HARNESS_MAX_RULES`로 변경 가능). 40을 넘으면 startup에서 `exit 3`.

---

## 3. 룰 객체

```yaml
- id: <unique_snake_case>          # 룰 내부 id (audit 로그 키)
  tool:
    name: ssh_<lowercase_underscore>   # MCP 툴 이름. /^[a-z][a-z0-9_]{0,63}$/
    description: |
      LLM이 읽을 설명. 다음을 포함하세요:
        - 무엇을 하는지 (실행되는 명령 한 줄)
        - 언제 써야 하는지 / 언제 쓰면 안 되는지
        - 부작용 없음 ("read-only")
  params:
    <param_name>:
      type: ...
      ...
  template:
    host: "{host}"                  # 항상 placeholder. 보통 "{host}"
    argv: [<literal>, "{param}"]    # 각 entry는 literal 또는 단일 {placeholder}
```

### `id` vs `tool.name`
- `id`는 룰 식별자 (allowlist 내부 + audit 로그에 기록).
- `tool.name`은 LLM이 보는 함수명. 관례: `ssh_<verb>_<noun>` (`ssh_harness_get_uptime`, `ssh_list_containers`).
- 둘 다 unique해야 함. 중복 시 startup error.

### `description` 작성 팁
- LLM은 description을 보고 호출 여부를 결정합니다. **언제 쓰지 말아야 하는지**를 함께 적어두면 잘못된 호출이 줄어듭니다.
- 예: `"Use when: diagnosing disk pressure — not for CPU/memory consumers."`
- 그러나 description은 보안 가드가 아닙니다. 실제 강제는 `params` enum/pattern과 `argv` 리터럴이 합니다.

---

## 4. params 스펙

모든 param은 다음 형태:

```yaml
<param_name>:
  type: string | integer
  enum: [...]                # string: enum 또는 pattern 필수
  pattern: '<regex>'         # string: enum 또는 pattern 필수
  minimum: <int>             # integer: 옵션
  maximum: <int>             # integer: 필수
  default: <value>           # 옵션
  description: <text>        # 옵션 (LLM에 노출)
  secret: true               # 옵션. audit 로그에서 값 redact
```

### 4.1 type: string

**enum 또는 pattern 중 최소 하나는 반드시 있어야 함** (둘 다 가능 — `pattern` 먼저 적용 후 `enum`이 덮어씁니다, 사실상 enum이 우선).

#### enum (화이트리스트)
가장 안전하고 권장되는 방식.

```yaml
container:
  type: string
  enum: [api, worker, scheduler, nginx]
  description: 컨테이너 이름 (docker compose service)
```

- enum 항목은 모두 string이어야 함. 숫자 섞이면 lint error.
- 빈 배열도 lint error.
- 운영 중 새 컨테이너가 늘어나면 YAML 편집 + 재시작 필요. 이 마찰이 보안 의도와 일치합니다.

#### pattern (정규식)
enum으로 못 잡는 경우(가변 unit, 동적 namespace 등)에 사용.

```yaml
unit:
  type: string
  pattern: '^[a-z][a-z0-9@._-]*\.service$'
  description: systemd unit name (must end in .service)
```

**Pattern 작성 시 강제 규칙:**
- **자동 full-anchor (v1.0.4+):** pattern은 런타임에 `^(?:<pattern>)$`로 감싸져 **값 전체**에 매치됩니다 (`src/schema.ts`). 즉 `[a-z]+`도 `'foo-bar; rm -rf /'` 같은 superstring을 더 이상 통과시키지 않습니다. (이전에는 Zod `.regex()`의 부분 매치 때문에 통과했음 — 직접 `^...$`를 박지 않으면 위험했습니다.) 직접 `^`/`$`를 써도 무방하며 중복 적용은 무해합니다.
- **`-`로 시작하는 문자열을 매치하면 안 됨.** lint가 패턴을 full-anchor로 감싸 `-`, `--`, `-o`, `-oProxyCommand=...` 등 dash-leading 프로브로 테스트하여 매치되면 reject (`src/allowlist.ts` `patternRejectsDashLead`). argv에 `--` 구분자가 삽입되고 shell 없이 spawn하므로 이 검사는 심층 방어입니다.
  - `[a-zA-Z0-9]+` → OK (영숫자 강제)
  - `[\w-]+` → reject (dash로 시작 가능)
  - `.+` / `.*` → reject
- **nested quantifier 회피.** `(a+)+`, `(a*)*` 같은 ReDoS 패턴은 `[WARN]` 발생 (`UNSAFE_PATTERN_RE`).

```yaml
# v1.0.3 이하: 'foo-bar; rm -rf /' 가 부분매치로 통과했음. v1.0.4+에서는 자동 anchor로 전체값만 매치.
pattern: '[a-z]+'

# 명시적으로 써도 동일 (권장 — 의도가 분명)
pattern: '^[a-z][a-z0-9_-]*$'
```

### 4.2 type: integer

```yaml
lines:
  type: integer
  minimum: 1
  maximum: 1000        # ← 필수
  default: 200
  description: tail 라인 수
```

- **`maximum` 필수.** 없으면 startup error. 이유: `lines=999999999` 같은 어드버서리얼 값으로 host의 메모리/디스크/네트워크를 고갈시키는 것을 차단.
- `minimum`은 옵션이지만 거의 항상 1 이상으로 두는 게 안전. 음수/0이 의미 없는 거의 모든 케이스에서.
- Zod의 `z.number().int()`로 검증되므로 float은 거부됨.

### 4.3 default

- LLM이 값을 생략했을 때 채워지는 값.
- Zod의 `.default()`로 적용되므로 **JSON Schema에서는 optional**로 보입니다.
- 자주 쓰는 값은 default를 두면 LLM 호출이 훨씬 안정적이 됩니다.

### 4.4 secret: true

- audit 로그의 `params`와 `argv`에서 해당 값이 `[REDACTED]`로 치환됨 (`src/server.ts:244-251`).
- argv 토큰이 secret 값과 **정확히 일치**할 때만 redact. 부분 문자열은 그대로 노출되므로 `--token={token}` 같이 보간된 argv 토큰은 redact되지 않음 — 그런 케이스는 별도 placeholder로 분리하세요.
- 일반적인 진단 룰에는 secret이 거의 필요하지 않습니다. 토큰/패스워드를 argv에 박지 마세요.

---

## 5. template

### 5.1 host
- 거의 항상 `host: "{host}"` 패턴. params의 `host`를 그대로 받습니다.
- 정적으로 박을 수도 있음 (`host: "api-prod"`) 하지만 그러면 다중 host 지원 불가.

### 5.2 argv
- string 배열. 각 entry는 **literal 문자열** 또는 **단일 `{placeholder}` 문자열**.
- placeholder는 `{name}` 형태로 `params`의 키와 매칭. 매칭 실패 시 startup lint error.
- 치환은 `String.replace`로 단순히 값을 넣는 방식 (`src/template.ts:27-34`). 값은 spawnSync의 argv 원소로 그대로 들어가므로 **shell 보간 없음, quoting 불필요**.

```yaml
# 좋음 — 각 토큰이 별개 argv 원소
argv: [docker, logs, --tail, "{lines}", "{container}"]

# 좋음 — 명시적 옵션 분리
argv: [journalctl, -u, "{unit}", --since, "{since_minutes} minutes ago", --no-pager]

# 나쁨 — 한 토큰에 여러 placeholder 합치면 의미 흐려짐 (작동은 하지만 redact/audit가 부정확)
argv: [curl, "https://{host}:{port}/health"]
```

### 5.3 placeholder 규칙
- argv entry는 `{name}` 단일도 OK이고, `"prefix {name} suffix"`처럼 섞어도 OK. 단 모든 `{...}`는 params 키여야 함.
- `{host}`는 항상 `template.host`에 쓰입니다. argv 안에 `{host}`를 또 쓸 일은 거의 없음.
- placeholder가 params에 없으면 lint error: `[ERROR] rule "X": placeholder {foo} not found in params`.

### 5.4 mutation verb 차단
다음 `argv[0]`은 startup에서 reject (strict mode) 또는 `[WARN]` (loose):

- 직접 mutation: `rm`, `mv`, `cp`, `dd`, `kill`, `restart`, `reboot`, `shutdown`, `chmod`, `chown`, `truncate`
- `systemctl <start|stop|restart|disable|enable>`
- `docker <rm|stop|restart|kill>`

이 외에도 잠재적 mutation 명령(`apt`, `yum`, `dnf`, `pip install` 등)은 lint가 잡지 않으니 룰을 추가할 때 직접 검토하세요.

---

## 6. 룰 추가 워크플로우

1. **명령부터 명확히.** 추가하려는 진단을 host에서 직접 실행해 보고 read-only인지, 어떤 argv가 필요한지 확정합니다.
2. **YAML 편집.** `.ssh_harness/allowlist.yaml`에 룰 하나 추가.
3. **체크리스트:**
   - [ ] `id`가 unique
   - [ ] `tool.name`이 `^ssh_[a-z0-9_]+$`이고 unique
   - [ ] `argv[0]`이 read-only 동사
   - [ ] 모든 `{placeholder}`가 `params` 키에 존재
   - [ ] string param에 `enum` 또는 `pattern` (anchor 박힘)
   - [ ] integer param에 `maximum`
   - [ ] `description`에 use-when / use-not-when 명시
4. **lint 통과 확인:** `npm test` 또는 직접 `node bridge/server.js`로 서버 띄워서 startup banner에 rule count 확인.
5. **MCP Inspector로 호출 테스트:**
   ```bash
   npx @modelcontextprotocol/inspector@latest node bridge/server.js
   ```
6. **`.ssh_harness/audit.log` 확인:** 한 줄 JSON으로 invocation이 기록되는지.

---

## 7. 패턴 카탈로그 (복붙해서 변형)

### 7.1 host-only (인자 없는 상태 조회)
```yaml
version: 2
hosts:
  allowHosts: &hosts ["api-prod"]
  sshConfigRoot: "./ssh_config"

rules:
  - id: get_uptime
    tool:
      name: ssh_harness_get_uptime
      description: |
        Return host uptime and load averages (`uptime`). Read-only snapshot.
        Use when: confirming reachability and estimating load.
    params:
      host:
        type: string
        enum: *hosts
    template:
      host: "{host}"
      argv: [uptime]
```

### 7.2 enum 컨테이너 + 정수 윈도우
```yaml
- id: get_container_logs_tail
  tool:
    name: ssh_harness_get_container_logs_tail
    description: |
      Tail last N lines of a docker container's logs (`docker logs --tail N <c>`).
      Read-only. Use when: triaging recent errors for a specific service.
  params:
    host:
      type: string
      enum: *hosts
    container:
      type: string
      enum: [api, worker, scheduler, nginx, redis]
    lines:
      type: integer
      minimum: 1
      maximum: 1000
      default: 200
  template:
    host: "{host}"
    argv: [docker, logs, --tail, "{lines}", "{container}"]
```

### 7.3 systemd unit 패턴 + 시간 윈도우
```yaml
- id: get_journal_for_unit
  tool:
    name: ssh_harness_get_journal_for_unit
    description: |
      journalctl for a specific systemd unit over the last N minutes.
      Read-only. Use when: looking for unit-scoped errors in a recent window.
  params:
    host:
      type: string
      enum: *hosts
    unit:
      type: string
      pattern: '^[a-z][a-z0-9@._-]*\.service$'
      description: systemd unit name (must end in .service)
    since_minutes:
      type: integer
      minimum: 1
      maximum: 1440         # 24h cap
      default: 15
  template:
    host: "{host}"
    argv: [journalctl, -u, "{unit}", --since, "{since_minutes} minutes ago", --no-pager]
```

### 7.4 enum 네임스페이스 + enum 리소스 (k8s)
```yaml
- id: get_pods
  tool:
    name: ssh_harness_kubectl_get_pods
    description: |
      `kubectl get pods -n <ns> -o wide`. Read-only.
      Use when: enumerating pods in a known namespace; not for arbitrary cluster scans.
  params:
    host:
      type: string
      enum: *hosts
    namespace:
      type: string
      enum: [default, kube-system, monitoring, app]
  template:
    host: "{host}"
    argv: [kubectl, get, pods, -n, "{namespace}", -o, wide]
```

### 7.5 디스크 사용량 (path 패턴)
```yaml
- id: get_du_for_path
  tool:
    name: ssh_harness_get_du_for_path
    description: |
      Disk usage for an explicit absolute path (`du -sh <path>`). Read-only.
      Use when: checking which directory under /var or /opt is bloated.
  params:
    host:
      type: string
      enum: *hosts
    path:
      type: string
      pattern: '^/(var|opt|home|tmp)(/[a-zA-Z0-9._-]+)*$'
      description: absolute path under /var, /opt, /home, /tmp
  template:
    host: "{host}"
    argv: [du, -sh, "{path}"]
```

이 룰은 path를 사전 지정된 prefix에 가두어 `/etc/shadow` 같은 민감 경로 읽기를 차단합니다. anchor와 prefix를 동시에 강제하는 게 핵심.

---

## 8. Anti-patterns (자주 하는 실수)

### 8.1 anchor 빠진 pattern
```yaml
# 잘못 — 'foo; rm -rf /'도 부분 매치
pattern: '[a-z]+'

# 옳음
pattern: '^[a-z]+$'
```

### 8.2 dash-leading 허용
```yaml
# 잘못 — '--remove'도 매치됨 → ssh로 flag smuggling
pattern: '^[\w-]+$'        # \w는 _도 포함하지만 핵심은 dash 시작 가능
pattern: '^-?[a-z]+$'      # 명시적으로 dash 허용

# lint가 잡아서 startup에서 reject됨. 우회하지 말 것.
```

### 8.3 integer maximum 빠짐
```yaml
# 잘못 — startup에서 reject
lines:
  type: integer
  minimum: 1
  default: 100

# 옳음
lines:
  type: integer
  minimum: 1
  maximum: 1000
  default: 100
```

### 8.4 mutation verb 우회 시도
```yaml
# 잘못 — sh -c로 명령 합쳐서 lint 우회 시도
argv: [sh, -c, "df -h && rm /tmp/x"]   # argv[0]=sh가 lint를 통과해버림
```
**룰 카탈로그를 신뢰의 근거로 만들려면 sh/bash/zsh를 argv[0]로 두지 마세요.** 한 룰 = 한 read-only 명령이라는 불변식을 깨면 audit 로그도 의미를 잃습니다. 정 필요하다면 lint에 sh 차단을 추가하고 PR을 보내세요.

### 8.5 description으로 강제하려는 시도
```yaml
description: "use this only with positive integers"
# pattern/min/max로 강제하지 않으면 LLM이 description을 무시할 수 있음.
```
description은 LLM에 대한 힌트일 뿐 보안 강제력 없음. **모든 강제는 enum/pattern/min/max로.**

### 8.6 placeholder를 한 토큰에 여러 개
```yaml
# 작동은 하지만 secret redaction이 부정확해짐
argv: [curl, "https://{host}:{port}/api"]

# 옳음 — 각 값을 별개 argv 원소로
argv: [curl, --resolve, "{host}:{port}", "https://{host}/api"]
# 또는 docker 호스트 안에서 호출이라면 ssh layer를 두지 말 것
```

---

## 9. 런타임 강제 (참고)

YAML 작성 시 위 규칙을 지키면 startup에서 통과합니다. 호출 시점에는 다음이 추가로 적용됩니다 (`src/server.ts:138-170`):

1. **Zod `.strict()` 검증**: params에 없는 키가 들어오면 `schema_error`. enum/pattern/min/max 위반도 여기서 reject.
2. **Host 멤버십 defense-in-depth**: argument에 `host` 키가 있으면 `registry.hosts()`에 있는 값인지 한 번 더 확인. enum과 중복이지만 host param에 pattern을 쓴 경우의 안전망.
3. **Template 렌더링**: missing placeholder → `schema_error`.
4. **`spawnSync(sshBin, [..., host, '--', ...argv], { shell: false, env: { PATH: '/usr/bin:/bin' } })`**:
   - `-F .ssh_harness/ssh_config` 강제
   - `-o BatchMode=yes` (password prompt 차단)
   - `-o StrictHostKeyChecking=accept-new`
   - `-o ConnectTimeout=5`
   - `--` 이후 argv는 remote 명령으로 ssh가 받음 (literal argv, shell escape 없음)
5. **Audit append (fail-closed)**: 한 줄 JSON. 실패 시 `audit_failed` 이벤트 한 번 더 시도 후 호출 자체 fail (env로 best-effort 전환 가능).

---

## 10. 운영 체크리스트

- [ ] `version: 2`
- [ ] `hosts.allowHosts`의 모든 별칭이 resolved ssh_config(`hosts.sshConfigRoot` 또는 `~/.ssh/config`)에 `Host` 블록으로 선언됨
- [ ] `hosts.sshConfigRoot` 경로가 의도한 파일을 가리키는지 확인 (상대 경로는 allowlist.yaml 기준)
- [ ] 룰 cap (기본 40) 안쪽
- [ ] 룰별 lint 통과: 위 §6의 체크리스트
- [ ] `npm run build && npm test` 통과
- [ ] MCP Inspector로 신규 룰 1회 호출 → audit.log에 JSON 라인 확인. startup banner의 `ssh_config=` 라인이 의도한 경로인지 확인
- [ ] CODEOWNERS로 `.ssh_harness/` 변경에 security-ops 리뷰 강제 (GitHub/GitLab)

---

## 11. 참고

- 스키마 정의: `src/allowlist.ts` (Zod meta-schema, lint, `HostsBlock`)
- Param → Zod 변환: `src/schema.ts`
- 템플릿 렌더링: `src/template.ts`
- ssh 실행 / 타임아웃 / truncation: `src/exec.ts`
- 호출 파이프라인 + sshConfig 해소: `src/server.ts` (`createServer`, `executeRuleCall`)
- 경로 해소 로직: `src/config.ts` (`resolveSshConfigPath`)
- 환경 변수 / 기본 경로: `README.md` §Environment variables
- 참조 템플릿: `examples/allowlist.yaml`
