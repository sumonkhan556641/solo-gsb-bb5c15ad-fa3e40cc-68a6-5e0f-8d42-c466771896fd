# Local PEP 440 Dependency Resolver

一个完全本地化、确定性的依赖版本解析服务。使用 **Python + FastAPI + packaging**
实现，依据请求中自带的包版本清单（无需 PyPI、无需网络、无需账号）解析出全部
传递依赖。

## 特性

- **PEP 440 版本语义**：由 [`packaging`](https://packaging.pypa.io/) 提供版本号
  解析、排序与 `>=`、`==`、`<`、`~=`、`!=` 等说明符匹配；兼容 epoch、post、dev
  等版本形式。
- **传递依赖解析**：递归处理每个选定版本声明的依赖，支持依赖图中的环。
- **锁定优先**：`locks` 中给出的版本只要仍满足所有约束，就会被优先保留；
  锁定版本被更深层依赖证伪时，才按规则回溯到其他版本，返回结果里会说明每个锁的
  处置（`applied` / `backtracked` / `unsatisfiable` / `missing-version` /
  `not-found` / `unused`）。
- **确定性回溯**：其余候选严格按版本**从高到低**尝试；候选顺序、依赖处理顺序、
  根需求顺序均为确定顺序，相同输入永远得到相同输出（含尝试次数）。
- **默认排除预发布版**：`a/b/rc/dev` 等预发布默认不参与；可通过
  `allow_prereleases=true` 全局放开，或由显式预发布钉版（如 `==2.0rc1`）、
  对该包的锁自动放开。
- **可操作的冲突报告**：无解时返回 409，并给出：
  - 冲突包名与原因（`unsatisfiable` / `not-found` / `no-versions`）；
  - 互相矛盾的约束（说明符、提出者及其版本）；
  - 每条约束完整的**依赖路径**（从根一路到提出约束的包）；
  - 候选版本清单与已尝试版本，以及整棵失败分支树，而不是一句笼统错误。
- **PEP 508**：依赖可写成 `name[extra] spec; marker` 字符串；环境标记在固定的
  默认环境下求值（可用 `marker_env` 覆盖），保证结果可复现。
- **同步 + 异步两种用法**：`POST /resolve` 立即返回；`POST /jobs` 把同样的请求
  持久化到 SQLite 后由后台 worker 顺序执行，可查询、可协作取消，重启自动恢复。
- **根需求冲突诊断**：`POST /diagnose/root-conflict` 接收与 `/resolve` **完全相同
  的请求体**；完整输入无解时，按稳定顺序逐条暂删根需求并重新求解，返回一个
  **最小冲突根集合**——集合自身仍无解，但删去其中任一条即变为可解。集合条目保留
  原始需求文本与输入位置（重复项可区分），结论由对子集的实际重算得到，而非摘取
  某次回溯分支的冲突路径；初始求解或任一次复算触及 `max_attempts` 时返回
  `undetermined`，绝不把搜索触顶判作无解。
- **漏洞审计**：`POST /audit/vulnerabilities` 直接接收 `/resolve` 成功响应中的
  `resolved` 与 `dependency_graph`，对照本地公告列表（PEP 440 受影响范围）匹配
  已解析版本；每个命中项给出从 `<root>` 到该包的**全部最短路径**（支持环与菱形
  依赖，路径去重并按节点序列稳定排序），不可达命中单列为 `orphaned`。
- **许可证策略审计**：`POST /audit/licenses` 接收 `resolved` 与一份包名 → SPDX
  表达式映射，按本地 `allowed` / `denied` 标识符集合判定每个包的合规状态
  （`violation` / `compliant` / `unknown` / `missing`）。表达式由成熟的
  [`license-expression`](https://github.com/aboutcode-org/license-expression)
  库解析，支持括号、`AND`、`OR`、`WITH`（`WITH` 按 `AND` 分别判定许可证与例外）；
  响应给出规范化表达式与决定状态的标识符，任一表达式非法即整体返回 400。
- **重建计划**：`POST /plan/rebuild` 接收 `/resolve` 成功响应中的 `resolved`、
  `dependency_graph` 与本地变更包名列表，先沿反向依赖边传播得到全部受影响包，
  再把环依赖压缩为必须同批构建的组，按“依赖先于依赖者”输出可并行的 stages；
  每个受影响包还给出距最近 changed 包的最短反向路径，未安装的 changed 项单列。
- **依赖图关键节点审计**：`POST /audit/dependency-chokepoints` 接收 `/resolve`
  成功响应中的 `resolved` 与 `dependency_graph`，以 `<root>` 为入口，在允许环与
  菱形结构的有向图上找出每个可达包的**必经依赖**（支配者，任一路径都无法绕过）；
  再按每个必经包汇总其**独占支配**的下游包（支配树后代）及数量，结果稳定排序，
  `<root>` 不可达的包单列。
- **依赖闭包指纹**：`POST /audit/graph-fingerprints` 接收 `/resolve` 成功响应中
  的 `resolved` 与 `dependency_graph`，为 `<root>` 和每个包计算其可达**完整依赖
  闭包**的 SHA-256 指纹：闭包按规范包名、PEP 440 规范版本与去重后的有向边做
  确定性序列化，环与菱形结构中的节点只计一次；输入映射的插入顺序、边的给出顺序
  及重复边都不影响结果，闭包内版本或边变化只会改变能到达该变化的节点指纹；根不可
  达的包仍按各自闭包生成指纹，并单列在 `unreachable` 中。
- **环境矩阵分析**：`POST /analyze/environment-matrix` 接收与 `/resolve` 相同的
  `packages`、`root`、`locks`、`allow_prereleases`、`max_attempts`，外加 2～8 个
  名称唯一的环境（各自带 `marker_env`），对每个环境**独立**解析同一组根需求与
  传递依赖（PEP 508 标记按各环境求值，一个环境触顶或冲突不影响其他环境），并仅
  对成功环境汇总版本矩阵——区分“缺席”与具体版本，列出版本或存在性不同的包。
- **版本撤回分析**：`POST /analyze/version-withdrawal` 沿用 `/resolve` 的包清单、
  根需求、锁与解析选项，另指定一个要撤回的包版本；先对原清单求解基线，再**仅从
  本次请求的清单**移除该版本重新求解。撤回后的求解是对完整依赖约束的**整体重算**
  （不沿旧依赖图推断），两次都成功时列出新增、消失与版本改变的包，并返回撤回后的
  依赖图与锁处置；基线冲突、撤回后冲突与任一次搜索触顶分别给出明确状态，触顶不
  视为无解。
- **升级可行性分析**：`POST /analyze/upgrade-feasibility` 沿用 `/resolve` 的包清单、
  根需求、锁与求解选项，另指定一个目标包及 **1～8 个候选版本**。候选必须存在于
  包清单中、按 PEP 440 规范化后不得重复，否则返回 `400`。对每个候选，在**原始根
  需求之上临时追加**一条 `==<候选版本>` 的精确根约束（原始根约束不替换、仍参与），
  其余锁、标记环境与求解选项全部保留，用完整 `max_attempts` 预算**独立整体回溯**
  ——判定依据是全部传递约束而非目标包自身的版本区间；目标包上的锁与临时钉版冲突
  时照常被证伪回退。结果按候选输入顺序返回 `ok` / `conflict` / `undetermined` 及
  各自的尝试次数：成功项给出完整解析结果与**相对原锁（基线解析）的版本变更**，
  无解项给出结构化冲突摘要，搜索触顶判为 `undetermined`，**绝不视为不可安装**。
- **漏洞规避求解**：`POST /resolve/avoid-vulnerabilities` 沿用 `/resolve` 的包清单、
  根需求、锁与求解选项，另接收本地公告列表（`id`、`package`、`affected`）。求解前
  先按规范包名与 PEP 440 受影响范围，从**本次请求的清单副本**中删除全部命中版本
  （多条公告取**并集**），再在剩余候选上完整回溯——被公告排除的锁定版本不会被选回
  （报告为 `missing-version`）。成功时返回安全的 `resolved`、`dependency_graph`、
  `locks` 以及每条公告**实际排除的版本**与并集；无解返回 `conflict`，`max_attempts`
  触顶返回 `undetermined`（均为 409，触顶不视为无解），非法公告返回 `400`。

## 一条命令启动

需要 Docker（含 Compose v2）。在项目根目录执行：

```bash
docker compose up --build
```

服务监听 **http://localhost:8000**：

- `GET /health` — 健康检查
- `POST /resolve` — 同步解析依赖（保持原有行为不变）
- `POST /resolve/avoid-vulnerabilities` — 排除本地公告命中的版本后回溯求解安全版本
- `POST /diagnose/root-conflict` — 诊断最小冲突根需求集合（与 `/resolve` 同请求体）
- `POST /audit/vulnerabilities` — 用本地公告列表审计已解析的依赖图
- `POST /audit/licenses` — 用本地许可证策略审计已解析的包
- `POST /audit/dependency-chokepoints` — 审计依赖图的必经依赖（支配者/关键节点）
- `POST /audit/graph-fingerprints` — 为 `<root>` 与每个包的完整依赖闭包计算 SHA-256 指纹
- `POST /plan/rebuild` — 为本地变更包生成确定性的重建计划
- `POST /analyze/environment-matrix` — 在多个标记环境下独立解析并汇总版本矩阵
- `POST /analyze/version-withdrawal` — 撤回一个包版本后整体重算并对比解析结果
- `POST /analyze/upgrade-feasibility` — 对目标包的 1～8 个候选版本分别独立整体回溯，判定可升级性
- `POST /jobs` — 提交异步解析作业（立即返回 `202` 与作业 ID）
- `GET /jobs/{id}` — 查询作业状态与最终响应
- `DELETE /jobs/{id}` — 取消作业
- `GET /docs` — 交互式 OpenAPI 文档（Swagger UI）

镜像在构建时安装固定版本依赖；运行时不访问任何外部仓库。

## 异步作业 API

对于回溯很深、耗时较长的解析，可以用与 `/resolve` **完全相同的请求体**提交
一个持久化作业，由内置 worker 在后台顺序执行（FIFO）。状态保存在 SQLite 中，
服务重启、容器重建后作业与结果仍然保留（见[数据持久化](#数据持久化)）。

### 提交作业

```bash
curl -s -X POST localhost:8000/jobs -H 'Content-Type: application/json' -d '{
  "packages": { "x": {"1.0": {}, "2.0": {}} },
  "root": { "x": ">=1.0" }
}'
```

返回 `202 Accepted`，并通过 `Location: /jobs/{id}` 给出查询地址：

```json
{
  "id": "59150780924745849a94bbe17e0d5155",
  "status": "queued",
  "created_at": "2026-09-17T08:00:00.000000+00:00",
  "started_at": null,
  "finished_at": null
}
```

入队前会做与 `/resolve` 一致的语法/语义校验：非法请求直接返回 `400/422`，
不会产生注定失败的作业。

### 查询作业

```bash
curl -s localhost:8000/jobs/59150780924745849a94bbe17e0d5155
```

状态机：`queued → running → succeeded | failed | cancelled`。

- `queued` / `running`：返回时间戳；running 时若已请求取消，还会带
  `"cancel_requested": true` 与当前已求值的候选次数 `attempts`。
- `succeeded`：`response` 即同步 `/resolve` 的完整响应体，`response_status`
  为其原本的 HTTP 状态码（解析成功 `200`；无解/触顶为 `409`，与同步接口一致）。
- `failed`：作业执行出现异常，`error` 给出错误码与信息。
- `cancelled`：已取消（不包含 `response`，终态不可更改）。

### 取消作业

```bash
curl -s -X DELETE localhost:8000/jobs/{id}
```

- **queued**：立即转为 `cancelled`，返回 `200`；
- **running**：worker 在**下一个候选求值边界**协作式停止，作业随即变为
  `cancelled`（不会在回溯分支中途停在不一致状态），返回 `202`；
- **cancelled**：幂等，再次取消返回 `200`；
- **succeeded / failed**：终态受保护，返回 `409`，原结果不会被覆盖。

#### 取消与完成的线性化语义

对 running 作业，`DELETE` 与 worker 的写回由两条 `BEGIN IMMEDIATE` 事务按
**提交顺序**线性化，取消优先级完全在 `JobStore` 的单次终结事务内裁决，作业外
不做任何预检决策，因此不存在“检查时未取消、提交时已取消”的窗口：

- **取消先提交**（作业仍为 running 时 `cancel_requested=1` 已落盘）：即使解析器
  刚通过最后一次候选边界取消检查、worker 随后仍提交了成功结果或失败结果，终结
  事务也会在同一事务里把终态原子地写为 `cancelled`，并把 `response`、
  `response_status`、`error` 三列一并置空——已取消的作业永远观察不到任何结果或
  错误；`attempts`（已求值候选数）仍可保留。
- **完成先提交**：作业已为 `succeeded`/`failed` 后，后续 `DELETE` 返回 `409`，
  结果原样保留（即上文既有行为）。

两种交错顺序都有确定性并发测试覆盖：用线程事件把一方固定在“对方已提交之后”再
继续，不依赖 sleep 或时序运气。

### 崩溃恢复

worker 以单条 `BEGIN IMMEDIATE` 事务原子领取最早的 `queued` 作业（按入队顺序，
FIFO），因此即使将来扩容为多个 worker 也不会重复领取同一作业。每次启动时，
上一进程遗留的 `running` 作业会被退回 `queued` 重新排队；若遗留作业此前已收到
取消请求，则直接终结为 `cancelled`。

## 漏洞审计 API

`POST /audit/vulnerabilities` 接收 `/resolve` **成功响应**中的 `resolved` 与
`dependency_graph`，外加一份本地公告列表，按已解析版本匹配受影响的包：

```bash
curl -s -X POST localhost:8000/audit/vulnerabilities \
  -H 'Content-Type: application/json' -d '{
  "resolved": {"app": "1.0", "db": "1.0", "web": "2.0", "common": "1.5"},
  "dependency_graph": [
    {"source": "<root>", "source_version": "", "target": "app", "target_version": "1.0"},
    {"source": "app", "source_version": "1.0", "target": "db", "target_version": "1.0"},
    {"source": "app", "source_version": "1.0", "target": "web", "target_version": "2.0"},
    {"source": "db", "source_version": "1.0", "target": "common", "target_version": "1.5"},
    {"source": "web", "source_version": "2.0", "target": "common", "target_version": "1.5"}
  ],
  "advisories": [
    {"id": "CVE-2026-0001", "package": "common", "affected": ">=1.0,<1.6"}
  ]
}'
```

请求字段：

- `resolved`：包名 → 已解析版本（PEP 440），即 `/resolve` 的 `resolved`。
- `dependency_graph`：边列表，即 `/resolve` 的 `dependency_graph`；每条边含
  `source` / `source_version` / `target` / `target_version`（`<root>` 边的
  `source_version` 为空字符串）。
- `advisories`：本地公告列表，每条含 `id`、`package`、`affected`
  （受影响版本的 PEP 440 说明符，如 `>=1.0,<1.6`；空字符串表示全部版本）。

响应（200）：

```json
{
  "status": "ok",
  "summary": {"advisories": 1, "matches": 1, "orphaned": 0},
  "matches": [
    {
      "advisory": {"id": "CVE-2026-0001", "package": "common", "affected": ">=1.0,<1.6"},
      "package": "common",
      "version": "1.5",
      "paths": [
        [
          {"name": "<root>", "version": ""},
          {"name": "app", "version": "1.0"},
          {"name": "db", "version": "1.0"},
          {"name": "common", "version": "1.5"}
        ],
        [
          {"name": "<root>", "version": ""},
          {"name": "app", "version": "1.0"},
          {"name": "web", "version": "2.0"},
          {"name": "common", "version": "1.5"}
        ]
      ]
    }
  ],
  "orphaned": []
}
```

- `matches`：每条命中一项，含公告原文、命中包与版本，以及从 `<root>` 到该包的
  **全部最短路径**（菱形依赖会给出多条；路径去重并按节点序列稳定排序，相同输入
  永远得到相同输出）。图允许含环——路径枚举只在 BFS 层数递增的边上前进，绝不
  因环无限遍历。
- `orphaned`：版本命中但无法从 `<root>` 到达的包（无 `paths` 字段），单列以便
  人工核查。
- 版本匹配与求解器口径一致：按 PEP 440 说明符判定，已解析的预发布版本同样参与
  匹配。

## 依赖图关键节点审计 API

`POST /audit/dependency-chokepoints` 接收 `/resolve` **成功响应**中的 `resolved`
与 `dependency_graph`，以 `<root>` 为入口，在**允许环和菱形结构**的有向图上
找出每个可达包的必经依赖（支配者），并按每个必经包汇总其独占支配的下游包：

- 若从 `<root>` 到包 `v` 的**每一条**路径都经过包 `d`（任一路径都无法绕过），
  则 `d` 是 `v` 的**必经依赖**（dominator）。菱形依赖的两个分支因此不互为必经
  节点；而唯一入口包会支配其后方的整个依赖簇。
- 对每个必经包 `d`，汇总其**独占支配**的下游包：在支配树中以 `d` 为根的后代
  集合——即离开 `<root>` 后不经过 `d` 就完全无法到达的包（不含 `d` 自身）。
- 图允许含环（含自环）：支配关系用迭代数据流不动点算法在一般有向图上计算，
  天然正确处理强连通分量。
- 出现在 `resolved` 中但无法从 `<root>` 到达的包（包括只被不可达包引用的包）
  不参与计算，单列为 `unreachable`。

```bash
curl -s -X POST localhost:8000/audit/dependency-chokepoints \
  -H 'Content-Type: application/json' -d '{
  "resolved": {"app": "1.0", "db": "1.0", "web": "2.0", "common": "1.5"},
  "dependency_graph": [
    {"source": "<root>", "source_version": "", "target": "app", "target_version": "1.0"},
    {"source": "app", "source_version": "1.0", "target": "db", "target_version": "1.0"},
    {"source": "app", "source_version": "1.0", "target": "web", "target_version": "2.0"},
    {"source": "db", "source_version": "1.0", "target": "common", "target_version": "1.5"},
    {"source": "web", "source_version": "2.0", "target": "common", "target_version": "1.5"}
  ]
}'
```

请求字段：

- `resolved`：包名 → 已解析版本（PEP 440），即 `/resolve` 的 `resolved`。
- `dependency_graph`：边列表，即 `/resolve` 的 `dependency_graph`；校验口径与
  漏洞审计完全一致（无悬空边、版本必须与 `resolved` 一致、`<root>` 边的
  `source_version` 必须为空）。

响应（200，以上述菱形为例）：

```json
{
  "status": "ok",
  "summary": {"packages": 4, "reachable": 4, "unreachable": 0, "chokepoints": 1},
  "packages": [
    {"package": "app", "version": "1.0", "required_dependencies": []},
    {"package": "common", "version": "1.5", "required_dependencies": ["app"]},
    {"package": "db", "version": "1.0", "required_dependencies": ["app"]},
    {"package": "web", "version": "2.0", "required_dependencies": ["app"]}
  ],
  "chokepoints": [
    {
      "package": "app",
      "version": "1.0",
      "exclusive_count": 3,
      "exclusive_dominees": ["common", "db", "web"]
    }
  ],
  "unreachable": []
}
```

- `packages`：每个从 `<root>` 可达的包一项（按包名排序），`required_dependencies`
  为其全部必经依赖（不含自身与 `<root>`，按包名排序）。上例中 `db` 与 `web`
  都能到达 `common`，所以 `common` 可以绕过其中任意一个，二者都不是必经依赖。
- `chokepoints`：至少独占支配一个下游包的必经包，按 `exclusive_count` **降序**、
  包名升序稳定排序；`exclusive_dominees` 为其支配树后代（不含自身，按包名排序），
  `exclusive_count` 为其数量。
- `unreachable`：已解析但 `<root>` 不可达的包（带版本，按包名排序），单列以便
  人工核查；空图或空输入时全部（或无）包归入此项，`packages` 与 `chokepoints`
  为空。
- 相同输入（即使边的给出顺序不同或含重复边）永远得到相同输出。

校验规则（违反即返回 `400`，错误体与 `/resolve` 相同）：

- `resolved` 中的版本必须是合法 PEP 440 版本，包名规范化后不得重复，`<root>`
  为保留名（与漏洞审计共用同一套校验）；
- 边的 `source`（`<root>` 除外）与 `target` 必须出现在 `resolved` 中，否则
  视为悬空边；
- 边的 `source_version` / `target_version` 必须与 `resolved` 中对应版本一致
  （`<root>` 边的 `source_version` 必须为空）。

## 依赖闭包指纹 API

`POST /audit/graph-fingerprints` 接收 `/resolve` **成功响应**中的 `resolved` 与
`dependency_graph`，为 `<root>` 和**每个**已解析包计算其可达**完整依赖闭包**的
SHA-256 指纹：

- 节点的闭包 = 从它出发可达的全部节点（含自身，环与菱形中的节点只计一次）加上
  这些节点之间去重后的有向边；闭包按**规范包名**、**PEP 440 规范版本**与排序后
  的边做确定性序列化（规范 JSON），再取 SHA-256。
- 序列化前所有列表均已排序，因此 `resolved` 映射的插入顺序、边的给出顺序以及
  重复边都**不影响**指纹；相同闭包内容永远得到相同指纹。
- 闭包内任一版本或边发生变化，会改变**恰好能到达该变化**的节点（及 `<root>`）
  的指纹，与其无关的包指纹不变——可用于增量构建缓存键或变更影响面比对。
- 出现在 `resolved` 中但 `<root>` 不可达的包仍按**各自闭包**生成指纹（列在
  `packages` 中），同时单列在 `unreachable` 里；不可达内容不会混入根指纹。

```bash
curl -s -X POST localhost:8000/audit/graph-fingerprints \
  -H 'Content-Type: application/json' -d '{
  "resolved": {"app": "1.0", "left": "1.0", "right": "1.0", "shared": "1.5"},
  "dependency_graph": [
    {"source": "<root>", "source_version": "", "target": "app", "target_version": "1.0"},
    {"source": "app", "source_version": "1.0", "target": "left", "target_version": "1.0"},
    {"source": "app", "source_version": "1.0", "target": "right", "target_version": "1.0"},
    {"source": "left", "source_version": "1.0", "target": "shared", "target_version": "1.5"},
    {"source": "right", "source_version": "1.0", "target": "shared", "target_version": "1.5"}
  ]
}'
```

请求字段：

- `resolved`：包名 → 已解析版本（PEP 440），即 `/resolve` 的 `resolved`。
- `dependency_graph`：边列表，即 `/resolve` 的 `dependency_graph`；校验口径与
  漏洞审计完全一致（无悬空边、版本必须与 `resolved` 一致、`<root>` 边的
  `source_version` 必须为空）。

响应（200，以上述菱形为例）：

```json
{
  "status": "ok",
  "summary": {"packages": 4, "reachable": 4, "unreachable": 0},
  "root_fingerprint": "076fa588d8933035a38342337cec19d2f9a29b25c68006bcd2344978f0184118",
  "packages": [
    {"package": "app", "version": "1.0",
     "fingerprint": "17d739a96fdc2ba04d00ebecb4f0345e6d6fcf5bf01693961c702c788c0c4d76"},
    {"package": "left", "version": "1.0",
     "fingerprint": "78363271440acfe06dca27a9d6f30b95e857be62a9cf6a6ea9700190e126609f"},
    {"package": "right", "version": "1.0",
     "fingerprint": "841d348a4bf7e8b0b5bc14c466c4687e4912875c45d91c999c638c2a87f5a6ff"},
    {"package": "shared", "version": "1.5",
     "fingerprint": "616cc28664b5f3044aae80ccab83d5fe9d22923d4485fc4a490a12c9c19a2d84"}
  ],
  "unreachable": []
}
```

- `root_fingerprint`：`<root>` 闭包（全部可达包及其间边）的指纹。
- `packages`：**每个**已解析包一项（按包名排序），含规范化版本与各自闭包的
  指纹；上例中 `left` 与 `right` 的闭包同构，但包名参与哈希，故指纹不同。
- `unreachable`：已解析但 `<root>` 不可达的包（带版本，按包名排序）；这些包
  的指纹仍出现在 `packages` 中。
- 指纹为 64 位小写十六进制 SHA-256；相同输入（即使边的给出顺序不同或含重复
  边）永远得到相同输出。

校验规则（违反即返回 `400`，错误体与 `/resolve` 相同）：与漏洞审计、关键节点
审计共用同一套 `resolved` / `dependency_graph` 校验（合法 PEP 440 版本、规范化
后不重复、`<root>` 为保留名、无悬空边、边版本与 `resolved` 一致）。

## 许可证审计 API

`POST /audit/licenses` 接收 `/resolve` **成功响应**中的 `resolved`、一份
包名 → SPDX 许可证表达式映射，以及本地策略（`allowed` / `denied` 标识符集合），
对每个已解析包判定合规状态：

```bash
curl -s -X POST localhost:8000/audit/licenses \
  -H 'Content-Type: application/json' -d '{
  "resolved": {"app": "1.0", "web": "2.0", "db": "1.5", "util": "0.9"},
  "licenses": {
    "app": "MIT",
    "web": "(Apache-2.0 OR GPL-3.0-only) AND BSD-3-Clause",
    "db": "GPL-2.0-only WITH Classpath-exception-2.0"
  },
  "allowed": ["MIT", "Apache-2.0", "BSD-3-Clause", "Classpath-exception-2.0"],
  "denied": ["GPL-3.0-only"]
}'
```

请求字段：

- `resolved`：包名 → 已解析版本（PEP 440），即 `/resolve` 的 `resolved`。
- `licenses`：包名 → SPDX 许可证表达式（支持括号、`AND`、`OR`、`WITH`，大小写
  不敏感的已知 SPDX 标识符会规范化为标准写法）。未出现在 `resolved` 中的条目
  会被忽略（映射可以是超集，例如一份许可证知识库）；`resolved` 中没有条目的包
  记为 `missing`。
- `allowed` / `denied`：可选，SPDX 标识符列表（单项标识符，不能是表达式）。
  同一标识符同时出现在两个集合中时，`denied` 优先。

判定规则：

- 单个标识符：在 `denied` 中为 `violation`，在 `allowed` 中为 `compliant`，
  否则为 `unknown`。
- `AND`：任一操作数违规即 `violation`；否则任一未知即 `unknown`；否则
  `compliant`。
- `OR`：任一操作数合规即 `compliant`；否则任一未知即 `unknown`；否则
  `violation`。
- `WITH`：按 `AND` 处理，许可证与例外作为两个标识符分别判定。

响应（200）：

```json
{
  "status": "ok",
  "summary": {"packages": 4, "violation": 0, "compliant": 2, "unknown": 1, "missing": 1},
  "results": [
    {"name": "app", "version": "1.0", "status": "compliant",
     "expression": "MIT", "decisive": ["MIT"]},
    {"name": "db", "version": "1.5", "status": "unknown",
     "expression": "GPL-2.0-only WITH Classpath-exception-2.0",
     "decisive": ["GPL-2.0-only"]},
    {"name": "util", "version": "0.9", "status": "missing",
     "expression": null, "decisive": []},
    {"name": "web", "version": "2.0", "status": "compliant",
     "expression": "(Apache-2.0 OR GPL-3.0-only) AND BSD-3-Clause",
     "decisive": ["Apache-2.0", "BSD-3-Clause"]}
  ],
  "violation": [],
  "compliant": ["app", "web"],
  "unknown": ["db"],
  "missing": ["util"]
}
```

- `results`：每个已解析包一项，含规范化后的表达式与 `decisive`——**决定该状态
  的标识符**（如违规背后的 denied 标识符、使 `OR` 合规的 allowed 标识符）。
- `violation` / `compliant` / `unknown` / `missing`：按状态分组的包名清单。
- 所有清单与 `results` 均按规范化包名稳定排序，相同输入永远得到相同输出。

校验规则（违反即返回 `400`，错误体与 `/resolve` 相同，且不产生任何部分结果）：

- `resolved` 中的版本必须是合法 PEP 440 版本（与漏洞审计共用同一套校验）；
- 每个许可证表达式必须能解析为合法 SPDX 表达式（空字符串同样视为非法），
  全部非法表达式会在一次 400 中合并报告；
- `allowed` / `denied` 的每一项必须是单个 SPDX 标识符；
- 包名规范化后不得重复，`<root>` 为保留名。

## 重建计划 API

`POST /plan/rebuild` 接收 `/resolve` **成功响应**中的 `resolved` 与
`dependency_graph`，外加本地发生变更的包名列表 `changed`，为需要重建的包生成
确定性计划。规划分三步：

1. **反向传播**：从已安装的 changed 包出发，沿反向依赖边（“谁依赖我”）找出
   全部传递受影响包；
2. **环压缩**：在受影响子图上求强连通分量（SCC），同一环上的包压缩为一个
   必须同批构建的组（自环不会额外产生阶段）；
3. **分层排程**：按“依赖先于依赖者”给组分配阶段——一个组比它依赖的每个组
   晚一个阶段；同一阶段内的组之间没有依赖边，可以并行构建。

```bash
curl -s -X POST localhost:8000/plan/rebuild \
  -H 'Content-Type: application/json' -d '{
  "resolved": {"app": "1.0", "db": "1.0", "web": "2.0", "common": "1.5"},
  "dependency_graph": [
    {"source": "<root>", "source_version": "", "target": "app", "target_version": "1.0"},
    {"source": "app", "source_version": "1.0", "target": "db", "target_version": "1.0"},
    {"source": "app", "source_version": "1.0", "target": "web", "target_version": "2.0"},
    {"source": "db", "source_version": "1.0", "target": "common", "target_version": "1.5"},
    {"source": "web", "source_version": "2.0", "target": "common", "target_version": "1.5"}
  ],
  "changed": ["common", "numpy"]
}'
```

请求字段：

- `resolved`：包名 → 已解析版本（PEP 440），即 `/resolve` 的 `resolved`。
- `dependency_graph`：边列表，即 `/resolve` 的 `dependency_graph`；校验口径与
  漏洞审计完全一致（无悬空边、版本必须与 `resolved` 一致、`<root>` 边的
  `source_version` 必须为空）。
- `changed`：本地变更包名列表，按既有规则规范化（`Foo_Bar` 与 `foo-bar`
  视为同一个包，重复项合并）。出现在 `resolved` 中的作为传播起点；未出现的
  单列为 `uninstalled`，不参与传播。

响应（200）：

```json
{
  "status": "ok",
  "summary": {"changed": 1, "uninstalled": 1, "affected": 4, "groups": 4, "stages": 3},
  "changed": ["common"],
  "uninstalled": ["numpy"],
  "affected": ["app", "common", "db", "web"],
  "groups": [
    {"id": 0, "packages": ["common"], "changed": ["common"]},
    {"id": 1, "packages": ["db"], "changed": []},
    {"id": 2, "packages": ["web"], "changed": []},
    {"id": 3, "packages": ["app"], "changed": []}
  ],
  "stages": [[0], [1, 2], [3]],
  "rebuild_paths": [
    {"package": "common", "distance": 0,
     "path": [{"name": "common", "version": "1.5"}]},
    {"package": "db", "distance": 1,
     "path": [{"name": "db", "version": "1.0"},
              {"name": "common", "version": "1.5"}]},
    {"package": "web", "distance": 1,
     "path": [{"name": "web", "version": "2.0"},
              {"name": "common", "version": "1.5"}]},
    {"package": "app", "distance": 2,
     "path": [{"name": "app", "version": "1.0"},
              {"name": "db", "version": "1.0"},
              {"name": "common", "version": "1.5"}]}
  ]
}
```

- `changed` / `uninstalled`：已安装（参与规划）与未安装（仅报告）的规范化
  changed 包名，均按名称排序。
- `affected`：全部受影响包（含 changed 包本身），按名称排序。
- `groups`：压缩后的构建组；`changed` 字段标出组内的变更包。组按“依赖先于
  依赖者”的确定性顺序编号（Tarjan SCC 发射顺序，根与邻接均排序）。
- `stages`：每个阶段是一组可并行构建的组 id；阶段号严格按依赖关系递增
  （changed 叶子组位于阶段 0；若某个 changed 包还依赖另一个 changed 包，
  它会排在后续阶段，始终满足“依赖先于依赖者”）。
- `rebuild_paths`：每个受影响包距**最近** changed 包的最短反向路径（从该包
  沿依赖方向走到 changed 包，路径节点带已解析版本）；距离相同时按
  （距离, 包名）排序，等距路径按字典序最小的节点序列打破平局。

环依赖中的包会被压进同一个组、在同一个阶段整批重建；例如 `a ↔ b` 且 `a`
变更时，`{"a","b"}` 是阶段 0 的一个组，依赖它们的包进入后续阶段。相同输入
（即使边的给出顺序不同）永远得到相同的分组、阶段与路径顺序。

校验规则（违反即返回 `400`，错误体与 `/resolve` 相同）：

- `resolved` 中的版本必须是合法 PEP 440 版本；
- 边的 `source`（`<root>` 除外）与 `target` 必须出现在 `resolved` 中，否则
  视为悬空边；
- 边的 `source_version` / `target_version` 必须与 `resolved` 中对应版本一致
  （`<root>` 边的 `source_version` 必须为空）；
- `changed` 中的名称必须是非空字符串，规范化后不得为 `<root>`。

## 根需求冲突诊断 API

`POST /diagnose/root-conflict` 接收与 `/resolve` **完全相同的请求体**（`packages`、
`root`、`locks`、`allow_prereleases`、`marker_env`、`max_attempts`，校验规则也完全
一致），并复用同一套 PEP 440/508 解析规则，但不直接返回解，而是回答：**无解时，
哪些根需求必须同时存在才导致无解？**

完整输入无解时，按**稳定顺序**（根需求的原始输入顺序）逐条**暂删**一条根需求并
重新求解剩余集合（删除式最小化；同一轮输入顺序、同一份 locks、marker 环境与
`max_attempts` 预算）：

- 剩余集合**仍无解**：该条对冲突不是必需的，永久删除；
- 剩余集合**变为可解**：该条属于冲突集合，恢复保留。

该遍历会重复到一整轮都删不掉任何条目为止。最终返回的是一个**最小冲突根集合**：
集合自身仍无解，但删去其中**任一条**后剩余集合都可解。结论由对子集的**实际重算**
给出——求解器某次回溯分支的冲突路径只展示了众多失败方式中的一种，不能据此摘取
冲突根。

```bash
curl -s -X POST localhost:8000/diagnose/root-conflict \
  -H 'Content-Type: application/json' -d '{
  "packages": {
    "service-a": {"1.0": {"dependencies": {"libfoo": ">=2.0"}}},
    "service-b": {"1.0": {"dependencies": {"libfoo": "<2.0"}}},
    "libfoo": {"1.0": {}, "2.0": {}, "3.0": {}}
  },
  "root": ["service-a", "service-b"]
}'
```

响应（完整输入无解，HTTP 200）：

```json
{
  "status": "conflict",
  "attempts": 6,
  "allow_prereleases": false,
  "conflicting_roots": [
    {"index": 0, "package": "service-a", "requirement": "service-a",
     "specifier": "", "marker": null},
    {"index": 1, "package": "service-b", "requirement": "service-b",
     "specifier": "", "marker": null}
  ]
}
```

`conflicting_roots` 条目字段：

- `index`：该需求在**原始输入**中的零基位置（列表下标；映射形式则为映射的插入
  顺序下标），删除后其余条目的位置不重新编号。
- `requirement`：**原始需求文本**，逐字保留（列表形式即原字符串，如
  `"x>=1.0; python_version >= '3.11'"`；映射形式按 `<原键> <说明符>` 还原，如
  `"X ==2.0"`，不规范化键名拼写）。
- `package`：规范化后的目标包名；`specifier` 为解析后的说明符文本；`marker` 为
  环境标记文本或 `null`。

因此完全重复的根需求（或拼写不同但规范化后同名的需求）仍可凭 `index` 逐条区分；
最小集合不会因为重复项而被重复报告（暂删其中一条后另一条仍在，冲突依旧，重复项
会在最小化过程中被删掉，位置靠前的先被删）。

其他响应形态（HTTP 状态码均为 **200**，由 `status` 区分；请求体非法时与
`/resolve` 一样返回 `400/422`）：

- **可解**：`{"status": "ok", "attempts": 1, "allow_prereleases": false,
  "conflicting_roots": []}`。
- **未确定**：初始求解或**任一次复算**触及 `max_attempts` 时返回
  `{"status": "undetermined", ..., "conflicting_roots": null,
  "error": {"code": "search_limit_exceeded", "message": "..."}}`。搜索触顶不是无解
  的证据，因此既不会报告冲突集合，也不会把输入判作无解；`message` 会指出是初始
  求解触顶，还是暂删哪一条（带 `index` 与原始需求）后的复算触顶。

诊断过程是确定的：相同输入永远得到相同的冲突集合与 `attempts`（该字段汇总初始
求解与全部复算实际求值的候选次数）。注意最小冲突集合不唯一时，结果取决于上述
稳定删除顺序，但恒为“删任一条即可解”的最小集合。

## 环境矩阵分析 API

`POST /analyze/environment-matrix` 接收与 `/resolve` 相同的 `packages`、`root`、
`locks`、`allow_prereleases`、`max_attempts`（校验规则完全一致；**不含**顶层
`marker_env`），外加 2～8 个名称唯一的环境，每个环境带自己的可选 `marker_env`。
服务对每个环境**独立**解析同一组根需求与传递依赖——PEP 508 标记按各环境的
`marker_env` 求值——再对成功环境汇总版本矩阵：

- 每个环境独立占用完整的 `max_attempts` 预算：某个环境触顶（`limit`）或冲突
  （`conflict`）不影响其他环境的结果，各自的 `status` 与 `attempts` 都保留。
- 每个环境的结果体与 `/resolve` 同形态：`ok` 时带 `resolved` / `dependency_graph`
  / `locks`；`conflict` 时带结构化 `conflict`；`limit` 时另带
  `error.code = "search_limit_exceeded"`。
- 版本矩阵只汇总**成功**（`ok`）环境：每个包一行，`versions` 按环境名列出该环境
  解析出的具体版本或 `null`（**缺席**，即该环境的解中不含此包）；`differences`
  列出版本或存在性不同的包。成功环境少于两个时 `differences` 为空。
- 环境一律按**输入顺序**出现，包按**规范名称**排序；相同输入永远得到相同输出。

```bash
curl -s -X POST localhost:8000/analyze/environment-matrix \
  -H 'Content-Type: application/json' -d '{
  "packages": {
    "app": {"1.0": {"dependencies": [
      "tomli>=1.0; python_version < '"'"'3.11'"'"'",
      "common>=1.0"
    ]}},
    "tomli": {"1.0": {}, "2.0": {}},
    "common": {"1.0": {}, "2.0": {}}
  },
  "root": ["app"],
  "environments": [
    {"name": "py310", "marker_env": {"python_version": "3.10"}},
    {"name": "py311", "marker_env": {"python_version": "3.11"}}
  ]
}'
```

响应（HTTP 200；`dependency_graph` 从略）：

```json
{
  "status": "ok",
  "allow_prereleases": false,
  "summary": {"environments": 2, "ok": 2, "conflict": 0, "limit": 0},
  "environments": [
    {
      "name": "py310",
      "status": "ok",
      "attempts": 3,
      "resolved": {"app": "1.0", "common": "2.0", "tomli": "2.0"},
      "locks": {}
    },
    {
      "name": "py311",
      "status": "ok",
      "attempts": 2,
      "resolved": {"app": "1.0", "common": "2.0"},
      "locks": {}
    }
  ],
  "matrix": {
    "environments": ["py310", "py311"],
    "packages": [
      {"package": "app", "versions": {"py310": "1.0", "py311": "1.0"}},
      {"package": "common", "versions": {"py310": "2.0", "py311": "2.0"}},
      {"package": "tomli", "versions": {"py310": "2.0", "py311": null}}
    ],
    "differences": ["tomli"]
  }
}
```

请求字段：

- `packages` / `root` / `locks` / `allow_prereleases` / `max_attempts`：与
  `/resolve` 完全相同（见[请求格式](#请求格式)）。
- `environments`：2～8 个环境，按输入顺序比较。每项含：
  - `name`：非空标签，请求内必须唯一；
  - `marker_env`：可选，该环境的 PEP 508 标记求值覆盖（在固定的默认环境上
    叠加，语义与 `/resolve` 的 `marker_env` 一致）。

响应字段：

- `environments`：每个环境一项（输入顺序），含 `name`、`status`
  （`ok` / `conflict` / `limit`）、`attempts` 及该状态对应的 `/resolve` 式结果体。
- `matrix.environments`：参与矩阵的成功环境名（输入顺序）。
- `matrix.packages`：在任一成功环境中出现过的每个包一行（按规范名称排序），
  `versions` 逐环境给出版本或 `null`。
- `matrix.differences`：版本或存在性在成功环境间不一致的包（按规范名称排序）；
  成功环境少于两个时为空。

校验规则（与 `/resolve` 相同的输入校验全部复用）：

- `packages` / `root` / `locks` 非法时返回与 `/resolve` 相同的 `400`；
- 环境数量不在 2～8、缺 `name`、名字为空或含多余字段时返回 `422`；
- 环境名重复时返回 `400`（`invalid_request`）。

## 版本撤回分析 API

`POST /analyze/version-withdrawal` 接收与 `/resolve` **完全相同的请求字段**
（`packages`、`root`、`locks`、`allow_prereleases`、`marker_env`、`max_attempts`，
校验规则完全一致），外加一个 `withdraw` 目标（要撤回的包名与版本），回答：
**如果该版本从包清单中消失，解析结果会怎样变化？**

- 先在**未修改的清单**上求解基线；再把**本次请求的清单**复制一份、仅移除
  `withdraw` 指定的那个版本（其余版本、根需求、锁、标记环境与 `max_attempts`
  预算全部不变），重新求解。
- 撤回后的求解是对**完整依赖约束的整体重算**——由求解器从头回溯，而不是沿
  旧依赖图推断——因此撤回引发的回退版本、新引入或被丢弃的传递依赖都会被
  重新计算。
- 包名与版本按清单自身规则规范化（`Foo_Bar` 与 `foo-bar`、`1.0` 与 `1.0.0`
  视为同一条目）；`withdraw` 的包或版本在清单中不存在时返回 `400`。
- 即使撤回的是某包的最后一个版本，该包仍留在清单中（版本列表为空），求解器
  会将其报告为“无可用版本”而非“包不存在”。

```bash
curl -s -X POST localhost:8000/analyze/version-withdrawal \
  -H 'Content-Type: application/json' -d '{
  "packages": {
    "app": {"1.0": {"dependencies": {"web": ""}}},
    "web": {"3.0": {"dependencies": {"common": ">=2.0"}},
            "2.0": {"dependencies": {"common": "<2.0", "extra": ""}}},
    "common": {"1.5": {}, "2.0": {}},
    "extra": {"1.0": {}}
  },
  "root": {"app": ""},
  "withdraw": {"package": "web", "version": "3.0"}
}'
```

响应（两次求解都成功，HTTP 200）：

```json
{
  "status": "ok",
  "attempts": 7,
  "allow_prereleases": false,
  "withdraw": {"package": "web", "version": "3.0"},
  "changes": {
    "added": [{"package": "extra", "version": "1.0"}],
    "removed": [],
    "changed": [
      {"package": "common", "from": "2.0", "to": "1.5"},
      {"package": "web", "from": "3.0", "to": "2.0"}
    ]
  },
  "baseline_resolved": {"app": "1.0", "common": "2.0", "web": "3.0"},
  "resolved": {"app": "1.0", "common": "1.5", "extra": "1.0", "web": "2.0"},
  "dependency_graph": [ ... ],
  "locks": {}
}
```

响应字段（`status: "ok"` 时）：

- `withdraw`：实际撤回的规范化包名与版本（回显）。
- `changes`：两次成功结果的对比——`added`（撤回后新出现的包）、`removed`
  （消失的包）、`changed`（版本改变的包，含 `from` / `to`），均按规范包名
  稳定排序。
- `baseline_resolved`：基线解（包名 → 版本）。
- `resolved` / `dependency_graph` / `locks`：**撤回后**的解、依赖图与每个锁的
  处置（与 `/resolve` 成功响应同形态；锁定版本恰好被撤回时会报告为
  `missing-version`）。
- `attempts`：两次求解实际求值的候选次数之和。

其他响应形态（HTTP 状态码均为 **200**，由 `status` 区分）：

- **基线冲突**：`status: "baseline_conflict"`，带基线求解的 `locks` 与结构化
  `conflict`（与 `/resolve` 冲突响应同形态）；没有基线解，不做任何对比。
- **撤回后冲突**：`status: "withdrawn_conflict"`，带 `baseline_resolved` 以及
  撤回后求解的 `locks` 与结构化 `conflict`。
- **未确定**：任一次求解触及 `max_attempts` 时返回 `status: "undetermined"`
  与 `error.code = "search_limit_exceeded"`，`message` 指明是基线求解还是撤回后
  求解触顶；触顶**不视为无解**，因此不会报告 `changes` 或 `conflict`。

结果顺序稳定：相同输入永远得到相同的 `changes`、`attempts` 与依赖图。校验规则
（违反即返回 `400/422`，错误体与 `/resolve` 相同）：`packages` / `root` /
`locks` 的校验与 `/resolve` 完全一致；`withdraw` 缺字段、含多余字段、包名或
版本为空返回 `422`，包或版本在清单中不存在（或版本不是合法 PEP 440）返回
`400`。

## 升级可行性分析 API

`POST /analyze/upgrade-feasibility` 接收与 `/resolve` **完全相同的请求字段**
（`packages`、`root`、`locks`、`allow_prereleases`、`marker_env`、
`max_attempts`，校验规则完全一致），外加一个目标包名 `package` 和 **1～8 个
候选版本** `candidates`，回答：**把目标包钉到这些精确版本之一，整个项目能否
重新解析出来？**

- 对每个候选，在**原始根需求之上临时追加**一条根约束
  `package == <候选版本>`（原始根约束**不替换、仍参与求解**），再用与
  `/resolve` 相同的完整确定性回溯求解。原始 `locks`（含其他包的锁）、
  `marker_env`、`allow_prereleases` 在每个候选求解中全部照常生效；每个候选
  **独立**求解并各自拥有**完整的 `max_attempts` 预算**，前一个候选冲突或触顶
  不会消耗后一个候选的预算。
- 因此判定依据是**全部传递依赖约束的整体重算**，而不是只检查目标包自身的
  版本区间：即使候选版本本身满足所有针对目标包的直接约束，它要求的传递版本
  与项目其余部分矛盾时仍判为冲突。目标包上的锁若与临时钉版矛盾，会被求解器
  照常证伪（`locks` 记为 `unsatisfiable`）后尝试钉版。
- 服务先对**未修改的原始输入**求解一次**基线**（即“当前锁定状态”），仅供
  成功候选计算版本变更；基线本身冲突或触顶**不阻止**任何候选独立求解。
- 候选必须存在于该目标包的清单版本中，且按 PEP 440 规范化后不得重复，否则
  返回 `400`；候选数量、字段形状错误返回 `422`。

```bash
curl -s -X POST localhost:8000/analyze/upgrade-feasibility \
  -H 'Content-Type: application/json' -d '{
  "packages": {
    "app": {"1.0": {"dependencies": {"web": "", "db": ""}}},
    "web": {"3.0": {"dependencies": {"common": ">=2.0"}},
            "2.0": {"dependencies": {"common": "<2.0"}}},
    "db":  {"1.0": {"dependencies": {"common": "==1.5"}}},
    "common": {"1.5": {}, "2.0": {}}
  },
  "root": {"app": ""},
  "package": "web",
  "candidates": ["3.0", "2.0"]
}'
```

`web 3.0` 要求 `common>=2.0`，而 `db` 钉住 `common==1.5`，所以强制 `web==3.0`
因**传递约束**矛盾而无解（与 `web` 自身的版本区间无关）；`web 2.0` 可行。
响应（HTTP 200；`dependency_graph` 从略）：

```json
{
  "status": "ok",
  "allow_prereleases": false,
  "target": {"package": "web"},
  "summary": {"candidates": 2, "ok": 1, "conflict": 1, "undetermined": 0},
  "baseline": {"status": "ok", "attempts": 5},
  "candidates": [
    {
      "candidate": "3.0",
      "status": "conflict",
      "attempts": 3,
      "locks": {},
      "conflict": {
        "terminal_conflicts": [
          {
            "package": "common",
            "reason": "unsatisfiable",
            "message": "no version of 'common' satisfies all active constraints",
            "available_versions": ["2.0", "1.5"],
            "attempted_versions": [],
            "active_constraints": [
              {"requirement": "common==1.5", "required_by": "db",
               "required_by_version": "1.0",
               "path": [{"name": "<root>", "version": ""},
                        {"name": "app", "version": "1.0"},
                        {"name": "db", "version": "1.0"}]},
              {"requirement": "common>=2.0", "required_by": "web",
               "required_by_version": "3.0",
               "path": [{"name": "<root>", "version": ""},
                        {"name": "web", "version": "3.0"}]}
            ],
            "rejected_by": []
          }
        ],
        "tree": { "...": "完整的失败分支树（与 /resolve 冲突响应同形态）..." }
      }
    },
    {
      "candidate": "2.0",
      "status": "ok",
      "attempts": 4,
      "resolved": {"app": "1.0", "common": "1.5", "db": "1.0", "web": "2.0"},
      "dependency_graph": [ "..." ],
      "locks": {},
      "changes_relative_to": "baseline",
      "changes": {"added": [], "removed": [], "changed": []}
    }
  ]
}
```

顶层字段：

- `target`：规范化后的目标包名。
- `summary`：候选总数与 `ok` / `conflict` / `undetermined` 的计数。
- `baseline`：未修改输入的基线求解结果——成功时仅含 `status: "ok"` 与
  `attempts`；冲突时另带 `locks` 与结构化 `conflict`（同 `/resolve` 形态）；
  触顶时另带 `error.code = "search_limit_exceeded"`。基线只决定变更对比基准，
  不影响候选求解。
- `candidates`：**严格按候选输入顺序**给出的逐项结果，每项含 `candidate`
  （清单自身规范化后的版本字符串）与该次独立求解的 `attempts`。

候选项的三种状态（HTTP 状态码均为 **200**，由 `status` 区分）：

- **`ok`**：可安装。带完整的 `resolved`、`dependency_graph`、`locks`
  （均与 `/resolve` 成功响应同形态），以及
  `changes_relative_to` + `changes`：
  - `changes` 与版本撤回分析同形态——`added`（新出现的包）、`removed`
    （消失的包）、`changed`（版本改变的包，含 `from` / `to`），均按规范
    包名排序；
  - `changes_relative_to: "baseline"` 表示与基线解析（当前锁定状态）对比。
    基线本身无解或触顶时退而与请求的显式 `locks` 映射对比，取值为
    `"locks"`（此时 `added`/`removed` 按“有无显式锁”理解，仅在无可用基线时
    出现）。
- **`conflict`**：**在完整约束下确实无解**。带 `locks` 与结构化 `conflict`
  （与 `/resolve` 冲突响应同形态：终态冲突、可用/已尝试版本、每条矛盾约束
  的完整依赖路径与失败分支树），不含 `resolved` / `changes`。
- **`undetermined`**：该候选的独立求解触及 `max_attempts`。带 `attempts`、
  诊断性 `conflict` 与 `error.code = "search_limit_exceeded"`，`message` 会
  指出是哪个候选触顶。搜索触顶**不是不可安装的证据**，因此绝不会报成
  `conflict`。

校验规则（与 `/resolve` 相同的输入校验全部复用）：

- `packages` / `root` / `locks` 非法时返回与 `/resolve` 相同的 `400`；
- 目标包不在清单中、某候选版本不是合法 PEP 440、不在该包的可用版本中，
  或多个候选按 PEP 440 规范化后重复（如 `1.0.0` 与 `1.0`），返回 `400`
  （`invalid_request`；所有候选问题会合并到一次错误里，并列出可用版本）；
- 候选数量不在 1～8、缺 `package` / `candidates`、`package` 为空字符串、
  含多余字段时返回 `422`。包名与版本按清单同规则规范化（`Foo_Bar` 与
  `foo-bar` 视为同一包）。

## 漏洞规避求解 API

`POST /resolve/avoid-vulnerabilities` 接收与 `/resolve` **完全相同的请求字段**
（`packages`、`root`、`locks`、`allow_prereleases`、`marker_env`、
`max_attempts`，校验规则完全一致），外加一份**本地公告列表** `advisories`，直接
求解出一个不含任何已知受影响版本的方案——无需先 `/resolve` 再审计、再手工改锁。

- 每条公告含 `id`（本地标识）、`package`（受影响包名）、`affected`（受影响版本的
  PEP 440 说明符，如 `>=1.0,<1.6`；空字符串表示全部版本）。包名与清单同规则
  规范化（`Foo_Bar` 与 `foo-bar` 视为同一包）。
- 求解前，先把**本次请求的清单**复制一份，删除每条公告命中的版本：同一包被多条
  公告命中时取**并集**（只要任一公告排除，该版本就不可选）。原始清单不被修改，
  后续 `/resolve` 仍看得到被排除的版本。
- 之后在剩余候选上运行与 `/resolve` 相同的**完整确定性回溯**（锁优先、其余候选
  从高到低、PEP 508 标记照常求值），而不是沿某次旧解析结果推断；排除引发的
  回退版本、新引入或丢弃的传递依赖都由求解器整体重算。
- **被排除的锁定版本不会被选回**：它已不在精简后的清单中，锁处置记为
  `missing-version`；未命中的锁仍按“锁优先”正常生效。
- 某包版本被全部排除时，该包仍留在清单中（版本列表为空），冲突原因为
  `no-versions` 而非“包不存在”。
- 公告指向清单中不存在的包不算错误：该公告实际排除版本为空。
- 版本命中口径与漏洞审计一致：按 PEP 440 说明符对清单中的具体版本判定，
  预发布版本落在范围内同样会被排除（即使 `allow_prereleases=false`）。

```bash
curl -s -X POST localhost:8000/resolve/avoid-vulnerabilities \
  -H 'Content-Type: application/json' -d '{
  "packages": {
    "app": {"1.0": {"dependencies": {"web": ""}}},
    "web": {"3.0": {"dependencies": {"common": ">=2.0"}},
            "2.0": {"dependencies": {"common": "<2.0"}}},
    "common": {"1.5": {}, "2.0": {}}
  },
  "root": {"app": ""},
  "advisories": [
    {"id": "ADV-WEB-3", "package": "web", "affected": ">=3.0"},
    {"id": "ADV-COMMON-2", "package": "common", "affected": ">=2.0,<3"}
  ]
}'
```

响应（找到安全方案，HTTP 200）：

```json
{
  "status": "ok",
  "attempts": 3,
  "allow_prereleases": false,
  "advisory_exclusions": [
    {"advisory": {"id": "ADV-WEB-3", "package": "web", "affected": ">=3.0"},
     "excluded_versions": ["3.0"]},
    {"advisory": {"id": "ADV-COMMON-2", "package": "common", "affected": ">=2.0,<3"},
     "excluded_versions": ["2.0"]}
  ],
  "excluded_versions": {"common": ["2.0"], "web": ["3.0"]},
  "resolved": {"app": "1.0", "common": "1.5", "web": "2.0"},
  "dependency_graph": [ ... ],
  "locks": {}
}
```

响应字段（`status: "ok"` 时）：

- `resolved` / `dependency_graph` / `locks`：安全方案，与 `/resolve` 成功响应
  同形态（`locks` 给出每个锁的处置；被公告排除的锁为 `missing-version`）。
- `advisory_exclusions`：按公告**输入顺序**逐条给出该公告在本次清单中**实际
  排除的版本**（规范包名、清单自身的规范版本字符串、从高到低排序）；公告包不
  在清单中或范围内没有清单版本时为空列表。
- `excluded_versions`：所有公告排除结果的**并集**（包名 → 版本列表，均排序；
  没有任何命中时为空对象），即本次求解实际不可选的全部版本。
- `attempts`：求解实际求值的候选次数。

其他响应形态（由 `status` 区分）：

- **无解**：HTTP **409**，`"status": "conflict"`，带与 `/resolve` 冲突响应同形态
  的结构化 `conflict`（含可用版本、已尝试版本与每条矛盾约束的依赖路径）及
  `locks`、`advisory_exclusions`、`excluded_versions`；例如所有版本都被公告排除
  时终端原因为 `no-versions`。
- **未确定**：求解触及 `max_attempts` 时 HTTP **409**，`"status": "undetermined"`，
  并带 `"error": {"code": "search_limit_exceeded", ...}` 与诊断性 `conflict`。
  触顶**不视为无解**，可能只是预算不够。
- **非法公告**：HTTP **400**，错误体与 `/resolve` 一致（`invalid_request`），如
  `affected` 不是合法 PEP 440 说明符、`id` / `package` 为空。`packages` / `root`
  / `locks` 的校验与 `/resolve` 完全复用；缺 `advisories`、公告含多余字段等形状
  错误返回 `422`。

## 数据持久化

异步作业保存在 SQLite（WAL 模式），数据库路径由环境变量 `RESOLVER_DB` 控制，
默认 `./data/jobs.db`。`docker compose up --build` 通过命名卷 `resolver-data`
挂载到容器内的 `/app/data`，因此：

- 重建镜像、重启容器后，已排队和已完成的作业都还在；
- 未完成的作业在启动时自动重新入队执行。

如需清空历史，可删除卷：`docker compose down -v`。

## 请求格式

`/resolve`、`POST /jobs` 与 `/diagnose/root-conflict` 使用**完全相同**的请求体
（`/analyze/environment-matrix` 在此基础上把顶层 `marker_env` 换成 2～8 个各自
携带 `marker_env` 的 `environments`，其余字段一致；`/analyze/version-withdrawal`
则在与 `/resolve` 完全相同的字段之外增加一个 `withdraw: {"package", "version"}`
目标；`/analyze/upgrade-feasibility` 在与 `/resolve` 完全相同的字段之外增加
`package`（目标包名）与 `candidates`（1～8 个候选版本字符串）；
`/resolve/avoid-vulnerabilities` 在与 `/resolve` 完全相同的字段之外增加
`advisories: [{"id", "package", "affected"}]` 本地公告列表）：

```json
{
  "packages": {
    "<包名>": {
      "<PEP440版本>": {
        "dependencies": { "<依赖包名>": "<版本说明符>" }
      }
    }
  },
  "root": { "<包名>": "<版本说明符>" },
  "locks": { "<包名>": "<锁定版本>" },
  "allow_prereleases": false,
  "marker_env": { "python_version": "3.11" }
}
```

- `packages`：本地包索引，包名 → 版本 → 条目。`dependencies` 可以是
  `{包名: 说明符}` 映射，也可以是 PEP 508 字符串数组，例如
  `["requests>=2.0", "tomli; python_version < '3.11'"]`。
- `root`：根依赖，映射或 PEP 508 字符串数组均可。
- `locks`：可选锁定版本。
- `allow_prereleases`：可选，默认 `false`。
- `marker_env`：可选，覆盖标记求值环境。
- `max_attempts`：可选，候选求值上限（默认 100000）。

### 成功响应（200）

```bash
curl -s -X POST localhost:8000/resolve -H 'Content-Type: application/json' -d '{
  "packages": {
    "app": {"1.0": {"dependencies": {"web": ">=2.0", "db": ""}}},
    "web": {"2.0": {"dependencies": {"common": "<2.0"}},
            "3.0": {"dependencies": {"common": ">=2.0"}}},
    "db":  {"1.0": {"dependencies": {"common": "==1.5"}}},
    "common": {"1.5": {}, "2.0": {}}
  },
  "root": {"app": ""}
}'
```

`web 3.0` 要求 `common>=2.0`，与 `db` 的 `common==1.5` 冲突，于是回溯到
`web 2.0`：

```json
{
  "status": "ok",
  "attempts": 5,
  "resolved": {"app": "1.0", "common": "1.5", "db": "1.0", "web": "2.0"},
  "dependency_graph": [ ... ],
  "locks": {}
}
```

### 锁定优先

```json
{ "packages": {"x": {"1.0": {}, "2.0": {}}},
  "root": {"x": ">=1.0"},
  "locks": {"x": "1.0"} }
```

只要锁仍满足约束，`x` 解析为 `1.0`（而非最高的 `2.0`），`locks.x = "applied"`。

### 冲突响应（409）

```json
{
  "packages": {
    "service-a": {"1.0": {"dependencies": {"libfoo": ">=2.0"}}},
    "service-b": {"1.0": {"dependencies": {"libfoo": "<2.0"}}},
    "libfoo": {"1.0": {}, "2.0": {}, "3.0": {}}
  },
  "root": ["service-a", "service-b"]
}
```

返回（节选）：

```json
{
  "status": "conflict",
  "conflict": {
    "terminal_conflicts": [
      {
        "package": "libfoo",
        "reason": "unsatisfiable",
        "available_versions": ["3.0", "2.0", "1.0"],
        "active_constraints": [
          {
            "requirement": "libfoo>=2.0",
            "required_by": "service-a",
            "required_by_version": "1.0",
            "path": [{"name": "<root>"}, {"name": "service-a", "version": "1.0"}]
          },
          {
            "requirement": "libfoo<2.0",
            "required_by": "service-b",
            "required_by_version": "1.0",
            "path": [{"name": "<root>"}, {"name": "service-b", "version": "1.0"}]
          }
        ]
      }
    ],
    "tree": { "...": "完整的失败分支树（含每步尝试的版本）..." }
  }
}
```

错误请求（非 PEP 440 版本、非法说明符、多余字段等）返回 `400/422` 并附带原因。

## 本地开发（不使用 Docker）

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

运行测试：

```bash
pip install pytest httpx
pytest -q
```

本地运行时作业库默认创建在 `./data/jobs.db`（已加入 `.gitignore`），可用
`RESOLVER_DB=/path/to/jobs.db` 覆盖。

## 解析策略说明

- 每个包维护当前所有生效约束的交集；候选必须同时满足全部约束。
- 搜索采用带精确撤销日志的深度优先回溯：选定一个版本后施加其依赖并递归；
  更深层失败时，按逆序撤销该候选引入的全部约束、边与发现标记，再尝试下一候选。
- 求解器仅做“按时间顺序回溯”，保证完备：有解时一定能找到；无解时一定报告。
- 为防止病态输入无限膨胀，`max_attempts` 触顶会返回 `status: "limit"`（仍带
  结构化冲突信息）。

## 项目结构

```
app/
  resolver.py       # PEP 440/508 解析、候选排序、回溯求解器、冲突数据结构、取消点
  serialize.py      # 冲突树 / 终态冲突的 JSON 序列化
  diagnose.py       # 根需求冲突诊断：逐条暂删+复算的最小冲突根集合（搜索触顶返回未确定）
  environment_matrix.py # 环境矩阵：多标记环境独立求解、成功环境版本矩阵与差异汇总
  version_withdrawal.py # 版本撤回分析：基线求解、移除单版本后整体重算、新增/消失/变更对比
  upgrade_feasibility.py # 升级可行性分析：逐候选追加精确版本根约束、独立完整回溯、ok/conflict/undetermined 与相对原锁的变更
  avoid_vulnerabilities.py # 漏洞规避求解：公告命中版本取并集从清单副本排除、剩余候选完整回溯、逐公告实际排除版本
  audit.py          # 漏洞审计：公告匹配、图一致性校验、<root> 最短路径枚举
  chokepoint_audit.py # 关键节点审计：可达性、支配者不动点、支配树与独占支配汇总
  graph_fingerprints.py # 闭包指纹：可达闭包的确定性序列化与 SHA-256、不可达包单列
  license_audit.py  # 许可证审计：SPDX 表达式解析、AND/OR/WITH 策略求值、决定性标识符
  rebuild.py        # 重建计划：反向依赖传播、Tarjan 环压缩、依赖优先并行 stages、最短反向路径
  jobs.py           # SQLite 作业存储、BEGIN IMMEDIATE 原子领取、后台 worker
  main.py           # FastAPI 应用与 /resolve、/resolve/avoid-vulnerabilities、/diagnose/root-conflict、/audit/*、/plan/rebuild、/analyze/environment-matrix、/analyze/version-withdrawal、/analyze/upgrade-feasibility、/jobs、/health
tests/              # 端到端 API 测试（含漏洞审计/漏洞规避、关键节点、许可证审计、闭包指纹、重建计划、环境矩阵、版本撤回与升级可行性分析）、根冲突诊断测试（含随机暴力对照）、作业持久化/取消测试、求解器单元测试（含随机暴力对照）
data/               # 运行时生成：SQLite 数据库（RESOLVER_DB，已 gitignore）
Dockerfile
docker-compose.yml
requirements.txt
```
