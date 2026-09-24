# 数字资源供应链与溯源平台

这是一个面向代码、AI 模型、数据集和构建产物的后端服务基线。当前版本提供可运行的 HTTP 服务、健康检查、进程内的资源登记与查询、资源之间的依赖关系登记、拓扑查询与影响分析接口、按资源标识提交原始字节的内容校验接口、内容寻址的分块存储、组装与成品读取接口、分块上传会话状态查询接口、资源生命周期状态（晋级、撤回与隔离）接口、按资源登记与查询安全告警（漏洞）的接口、按资源登记与查询 SBOM 文档与许可证声明的接口、按资源登记与查询构建来源证明（provenance）的接口、按资源登记与查询准入策略并执行只读准入评估的接口、按资源即时计算风险评分的接口、按资源登记与查询通知记录的接口，以及全局镜像层缓存（写入、读取与状态查询）接口。

## 环境

- Python 3.11 或更高版本
- 当前基线没有第三方运行依赖

## 启动服务

在仓库根目录执行：

```bash
python -m provenance_api --host 127.0.0.1 --port 8000
```

镜像层缓存的总字节配额由 `--cache-quota` 启动参数指定，缺省为 `1048576` 字节；取值必须是十进制正整数，非法取值会拒绝启动并输出用法说明：

```bash
python -m provenance_api --host 127.0.0.1 --port 8000 --cache-quota 1048576
```

服务监听成功后，可以访问：

```text
GET /health
```

成功响应为 HTTP 200，响应体是 JSON：

```json
{"status":"ok"}
```

其他路径返回 HTTP 404 和 JSON 错误信息。服务可通过 `Ctrl+C` 正常停止。

## 资源接口

资源记录描述代码、模型、数据集或构建产物，并保留其 64 位十六进制内容摘要（digest）及来源（source）。所有资源数据仅保存在当前进程内存中，服务停止后自然清空，不会写入任何文件。

所有资源接口的响应都是紧凑 UTF-8 JSON，键顺序稳定并以换行结束。

### 登记资源：`POST /resources`

请求体必须是一个完整的 JSON 对象，字段如下：

| 字段 | 类型 | 是否必填 | 说明 |
| --- | --- | --- | --- |
| `name` | string | 是 | 非空资源名称 |
| `category` | string | 是 | `code`、`model`、`dataset`、`artifact` 之一，大小写无关 |
| `digest` | string | 是 | 64 位十六进制内容标识（如 SHA-256），统一按小写存储 |
| `source` | string | 否 | 非空来源描述；缺省为 `null` |

不允许额外未知字段。成功时返回 HTTP 201 及新资源，其中包含服务生成的稳定标识 `id`：

```bash
curl -s -X POST http://127.0.0.1:8000/resources \
  -H 'Content-Type: application/json' \
  -d '{"name":"model-a","category":"Model","digest":"A1B2C3D4E5F60000000000000000000000000000000000000000000000000000","source":"https://example.invalid/model-a"}'
```

```json
{"id":"…","name":"model-a","category":"model","digest":"a1b2c3d4e5f60000000000000000000000000000000000000000000000000000","source":"https://example.invalid/model-a"}
```

相同类别、名称与摘要的重复登记返回 HTTP 409（错误码 `duplicate_resource`），不会覆盖或合并原记录。

### 查询单个资源：`GET /resources/{id}`

按标识取得单条资源；标识为空或含路径分隔符（`/`、`\\`）时返回 HTTP 400，找不到时返回只读的 HTTP 404（错误码 `resource_not_found`），两种情况都不改变状态。

### 列出资源：`GET /resources`

不带任何查询参数时，按资源创建顺序返回当前进程中的全部资源，响应形状保持不变，空集合也是合法 JSON：

```json
{"resources":[]}
```

#### 筛选条件

可以使用下列查询参数筛选资源，多个条件同时给出时只保留全部匹配的记录，结果仍按资源创建顺序排列：

| 参数 | 匹配规则 |
| --- | --- |
| `category` | 取 `code`、`model`、`dataset`、`artifact` 之一，比较时忽略大小写；响应中的类别仍按小写输出 |
| `name` | 与登记名称做完整字符串比较，区分大小写，不做模糊匹配或空白修剪 |
| `digest` | 64 位十六进制内容标识，接受大小写混合输入，按与登记一致的小写规则比较 |

例如只查询模型类资源：

```bash
curl -s 'http://127.0.0.1:8000/resources?category=MODEL'
```

#### 分页

分页由 `limit` 与 `cursor` 两个参数控制：

- `limit` 缺省为 `50`，单页上限为 `100`；必须是十进制正整数。
- 首次请求不带 `cursor`，从匹配结果的首项开始。
- 用上次响应返回的 `next_cursor` 再次请求，并保持相同的筛选条件与 `limit`，即可续取下一页；续取结果紧接上一页之后，不重不漏。
- 还有后续资源时 `next_cursor` 为非空字符串；已经到末页时为 `null`。

只要请求中出现了任意筛选或分页参数，响应就依次包含 `resources` 与 `next_cursor` 两个字段：

```json
{"resources":[…],"next_cursor":null}
```

`cursor` 仅在签发它的进程内、且仅对相同的筛选条件与 `limit` 有效，不应手工构造或跨重启使用。

#### 列表请求的错误

下列情况都返回 HTTP 400（错误码 `invalid_request`），且不改变已登记的资源：

- 未知或重复的查询参数；
- `category` 或 `name` 为空值，或 `category` 不是四个合法类别之一；
- `digest` 不是 64 位十六进制字符串；
- `limit` 不是十进制正整数，或大于 `100`；
- `cursor` 伪造、损坏，或与当前筛选条件、`limit` 不符。

筛选没有命中时不是错误，返回空的 `resources` 和 `null` 的 `next_cursor`。

## 依赖关系接口

依赖关系同样只保存在当前进程内存中，服务停止或重启后随资源一起清空，不会写入任何文件，也不做任何签名或持久化校验。关系只在**已经登记**的资源之间建立。

### 登记依赖：`POST /resources/{id}/dependencies`

声明路径中的资源（起点 `resource_id`）依赖请求体中的 `dependency_id`。请求体必须是 JSON 对象，且只允许一个字段：

| 字段 | 类型 | 是否必填 | 说明 |
| --- | --- | --- | --- |
| `dependency_id` | string | 是 | 被依赖资源的标识；非空，且不得包含 `/`、`\\` |

成功返回 HTTP 201，响应体是描述该关系的紧凑 JSON，键序固定并以换行结束：

```bash
curl -s -X POST http://127.0.0.1:8000/resources/$A/dependencies \
  -H 'Content-Type: application/json' \
  -d '{"dependency_id":"<资源 B 的 id>"}'
```

```json
{"resource_id":"<资源 A 的 id>","dependency_id":"<资源 B 的 id>"}
```

冲突与错误：

- 相同方向的关系已存在时返回 HTTP 409（错误码 `duplicate_dependency`），不覆盖已有关系或资源。
- 自环（起点与依赖相同）或会引入环的关系返回 HTTP 409（错误码 `dependency_cycle`），图的状态保持不变。间接依赖闭合为环同样会被拒绝。
- 已经间接可达、但尚不存在的直接边不算重复也不算环，仍以 HTTP 201 建立。
- 起点资源或 `dependency_id` 指向的资源不存在时返回 HTTP 404（错误码 `resource_not_found`），不会自动建资源。

### 查询依赖：`GET /resources/{id}/dependencies`

返回起点资源**可达的全部依赖**（直接与间接），形状为：

```json
{"dependencies":["<id>", "..."]}
```

结果按资源的**登记顺序**稳定展开（而不是按建边顺序），每个资源只出现一次；没有任何依赖时返回空数组，仍是 HTTP 200。

### 影响分析：`GET /resources/{id}/impact`

返回**直接或间接依赖起点**的全部资源，即沿依赖边反向可达的集合，形状为：

```json
{"resources":["<id>", "..."]}
```

结果按登记顺序排列，**不包含起点自身**；没有受影响资源时返回空数组。

### 依赖接口的错误

- 路径标识为空，或含 `/`、`\\`，返回 HTTP 400（错误码 `invalid_request`），不执行任何操作。
- 请求体缺失、不是合法 UTF-8 JSON、顶层不是 JSON 对象、缺少 `dependency_id`、`dependency_id` 不是字符串/为空/含分隔符，或出现未知字段，均返回 HTTP 400（错误码 `invalid_request`）。
- 这些接口不接受查询参数；出现任意查询参数返回 HTTP 400（错误码 `invalid_request`）。
- 起点不存在时，两个查询接口都返回 HTTP 404（错误码 `resource_not_found`），且不改变状态。
- 对 `/resources/{id}/dependencies` 使用 `GET`、`POST` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET, POST`）；对 `/resources/{id}/impact` 使用 `GET` 之外的方法返回 HTTP 405（`Allow: GET`）。
- 任何非法请求都不会新增或修改资源、关系或分页游标。


### 错误响应与方法限制

- 请求体缺失、无法解码或顶层不是 JSON 对象，返回 HTTP 400（错误码 `invalid_request`），不改变状态、不留下半条记录。
- 字段类型错误、必填字段缺失、空名称、非法类别、非法摘要、额外未知字段同样返回 HTTP 400，不做部分接受。
- 资源路径收到未声明的方法时返回 HTTP 405（错误码 `method_not_allowed`，附带 `Allow` 头），仍是 JSON 错误且不改变资源。
- 错误响应体形如：`{"error":"<稳定错误码>","message":"<说明>"}`。

## 资源内容校验

对已登记的资源，可以按标识提交原始字节内容，由服务计算 SHA-256 并与登记摘要逐字比较。校验只读取提交内容，不改变任何资源、依赖关系、分页游标或进程内存中的其他状态，也不写入任何文件。

### 校验内容：`POST /resources/{id}/verify`

- 请求体是按 `Content-Length` 声明长度读取的原始字节流；`Content-Type` 必须为 `application/octet-stream`（大小写无关，不接受参数）。
- 空字节流（`Content-Length: 0`）是合法内容，同样计算摘要，不会被误判为缺失请求体。
- 服务对收到的字节计算 SHA-256，得到 64 位小写十六进制摘要，与登记摘要逐字比较。

成功时返回 HTTP 200，响应体为紧凑 UTF-8 JSON，键序固定并以换行结束：

```bash
curl -s -X POST http://127.0.0.1:8000/resources/$ID/verify \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @payload.bin
```

```json
{"id":"<资源 id>","digest":"<提交内容的 SHA-256 摘要>","valid":true}
```

| 字段 | 说明 |
| --- | --- |
| `id` | 被校验资源的标识 |
| `digest` | 对提交字节计算的 64 位小写十六进制 SHA-256 摘要 |
| `valid` | 计算摘要与登记摘要逐字相同为 `true`；内容可读但与登记摘要不一致为 `false`，不是服务错误 |

错误与边界：

- 标识为空或含 `/`、`\\`，返回 HTTP 400（错误码 `invalid_request`），且不读取业务数据。
- 携带任意查询参数，返回 HTTP 400（错误码 `invalid_request`），不留下部分结果。
- `Content-Type` 不是 `application/octet-stream`，返回 HTTP 400（错误码 `invalid_request`）。
- 缺少 `Content-Length`、长度不是非负十进制整数、读取失败，或实际字节数不足声明长度（字节流不完整），均返回 HTTP 400（错误码 `invalid_request`）。
- 标识格式合法但资源不存在，返回 HTTP 404（错误码 `resource_not_found`）。
- `POST` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: POST`）。
- 除上述请求体、响应字段与状态码外，不对其他输入形式（如传输编码、表单字段、内容参数）作兼容承诺。

## 分块存储、组装与成品读取

在内容校验之外，可以把一份资源内容拆成若干有序分块上传，由服务按序拼接、计算 SHA-256 并与登记摘要核对，成功后保存为该资源的**成品内容**供读取。分块会话、分块字节与成品内容都只保存在当前进程内存中，服务停止或重启后随资源一起清空，不写入任何文件。

### 上传分块：`POST /resources/{id}/chunks/{index}`

`{index}` 是该分块的序号，必须是十进制非负整数（即 `0`，或以 `1`–`9` 开头的数字串；不接受负号、小数点、空白或多余前导零），且严格小于本次上传声明的总块数。

请求要求：

- 请求体是按 `Content-Length` 声明长度读取的原始字节流，`Content-Type` 必须为 `application/octet-stream`（大小写无关，不接受参数）；空字节流（`Content-Length: 0`）是合法分块。
- 头部 `X-Total-Chunks` 给出总块数，必须是十进制正整数。
- 头部 `X-Content-Digest` 给出整份内容的目标摘要，必须是 64 位十六进制字符串（接受大小写混合，按小写比较）。
- 不接受查询参数；路径标识与序号均不得含 `/`、`\\`。

首个被接受的分块确定本次上传的总块数和目标摘要；之后每个分块都必须重复相同的两个头部值。分块可以乱序到达，序号也可以跳过，只要组装前全部收齐即可。

新分块成功返回 HTTP 201，响应体为紧凑 UTF-8 JSON，键序固定并以换行结束：

```bash
curl -s -X POST "http://127.0.0.1:8000/resources/$ID/chunks/0" \
  -H 'Content-Type: application/octet-stream' \
  -H 'X-Total-Chunks: 3' \
  -H "X-Content-Digest: $DIGEST" \
  --data-binary chunk-0.bin
```

```json
{"id":"<资源 id>","index":0,"total_chunks":3,"received_chunks":1,"digest":"<目标摘要>"}
```

| 字段 | 说明 |
| --- | --- |
| `id` | 资源标识 |
| `index` | 本次提交的分块序号 |
| `total_chunks` | 首个分块确定的总块数 |
| `received_chunks` | 当前已收齐的不同序号数量 |
| `digest` | 本次上传的目标摘要（小写） |

幂等与冲突：

- 相同序号用**完全相同的字节**重复提交返回 HTTP 200，响应形状与 201 相同，状态保持不变（幂等重试）。
- 相同序号已存在但字节不同，返回 HTTP 409（错误码 `chunk_conflict`），已有分块不被覆盖。
- 首个分块之后提交的 `X-Total-Chunks` 或 `X-Content-Digest` 与首个分块不一致，返回 HTTP 409（错误码 `chunk_conflict`），不写入本分块。
- 首个分块声明的目标摘要与资源登记摘要不一致，返回 HTTP 409（错误码 `digest_conflict`），不创建会话、不留下任何片段。

### 组装：`POST /resources/{id}/assemble`

请求不带请求体要求（不接受查询参数）。服务把所有分块按序号从小到大拼接，对整份内容计算 SHA-256：

- 尚未收齐 `0..total-1` 的全部序号时返回 HTTP 409（错误码 `chunks_incomplete`），已收分块原样保留，可以继续补传。
- 拼接结果的 SHA-256 与登记（首个分块确定）的目标摘要不一致时返回 HTTP 409（错误码 `digest_mismatch`），不生成成品，已收分块保留。
- 成功返回 HTTP 201，并把该资源的内容标记为完成：

```bash
curl -s -X POST "http://127.0.0.1:8000/resources/$ID/assemble"
```

```json
{"id":"<资源 id>","digest":"<成品内容的 SHA-256 摘要>","size":1234}
```

内容完成后再次上传分块或再次组装，均返回 HTTP 409（错误码 `content_already_complete`），既有字节不被覆盖。

### 查询上传会话：`GET /resources/{id}/chunks/status`

只读查询某个资源当前的分块上传会话，不读取请求体，也不接受查询参数。该接口不创建任何会话、不写入分块、不改变游标、生命周期、依赖关系或任何内容字节，可安全重复调用。

- 资源存在但**从未开始上传**（没有任何分块被接受）时返回 HTTP 409（错误码 `chunks_not_started`），且不会因此创建会话。
- 已经开始上传（无论是否收齐、是否组装过）时返回 HTTP 200，响应体为紧凑 UTF-8 JSON，键序固定（`id`、`digest`、`total_chunks`、`received_chunks`、`missing_chunks`、`complete`、`size`）并以换行结束：

```bash
curl -s "http://127.0.0.1:8000/resources/$ID/chunks/status"
```

```json
{"id":"<资源 id>","digest":"<目标摘要>","total_chunks":3,"received_chunks":2,"missing_chunks":[1,2],"complete":false,"size":null}
```

| 字段 | 说明 |
| --- | --- |
| `id` | 资源标识 |
| `digest` | 首个分块确定的整份内容目标摘要（小写） |
| `total_chunks` | 首个分块确定的总块数 |
| `received_chunks` | 当前已收齐的不同序号数量（相同字节的幂等重试不重复计数） |
| `missing_chunks` | 尚缺的序号数组，按数值升序排列；已收齐时为空数组 `[]` |
| `complete` | 组装成功为 `true`；尚未组装、缺块或组装失败均为 `false` |
| `size` | 组装成功后为成品的实际字节长度（空成品为 `0`）；在此之前为 `null` |

组装成功后再次查询仍为 HTTP 200：`missing_chunks` 为空数组、`complete` 为 `true`、`size` 为成品实际字节长度。组装因摘要不符（`digest_mismatch`）失败后，已收分块继续保留：查询仍返回 HTTP 200、`missing_chunks` 为空、`complete` 为 `false`、`size` 为 `null`，不会误报完成，也不会生成成品。

### 读取成品：`GET /resources/{id}/content`

- 成功时返回 HTTP 200，响应体**只包含成品的原始字节**（无 JSON 包装、无末尾换行），`Content-Type: application/octet-stream`，`Content-Length` 为准确字节数；空成品对应 `Content-Length: 0` 与空响应体。
- 标识合法但资源不存在，返回 HTTP 404（错误码 `resource_not_found`）。
- 资源存在但尚未组装完成（从未上传、分块未齐或组装失败），返回 HTTP 409（错误码 `content_not_complete`）。

```bash
curl -s "http://127.0.0.1:8000/resources/$ID/content" --output artifact.bin
```

### 分块接口的通用错误

- 路径标识为空或含 `/`、`\\`，或分块序号缺失、不是非负十进制整数、不小于总块数，返回 HTTP 400（错误码 `invalid_request`）。
- 携带任意查询参数，返回 HTTP 400（错误码 `invalid_request`）。
- 缺少或非法的 `X-Total-Chunks`、`X-Content-Digest`（含摘要不是 64 位十六进制），返回 HTTP 400（错误码 `invalid_request`）。
- `Content-Type` 不是 `application/octet-stream`，返回 HTTP 400（错误码 `invalid_request`）。
- 缺少 `Content-Length`、其值不是非负十进制整数，或实际字节数不足声明长度，返回 HTTP 400（错误码 `invalid_request`）；失败请求不会留下分块片段。
- 资源不存在返回 HTTP 404（错误码 `resource_not_found`）。
- 方法限制：`/resources/{id}/chunks/{index}` 与 `/resources/{id}/assemble` 仅允许 `POST`（`Allow: POST`）；`/resources/{id}/content` 与 `/resources/{id}/chunks/status` 仅允许 `GET`（`Allow: GET`）；其他方法返回 HTTP 405（错误码 `method_not_allowed`）。
- `/resources/{id}/chunks/status` 额外约定：资源存在但尚未开始上传时返回 HTTP 409（错误码 `chunks_not_started`）；该查询只读，任何情况下都不会新增会话、分块或成品。
- 除 JSON 错误响应外，成品读取成功时只返回原始字节。

## 资源生命周期

新登记的资源默认处于 `staged`（暂存）状态；生命周期状态只保存在当前进程内存中，服务停止或重启后全部回到默认的 `staged`，不会写入任何文件。生命周期操作只修改状态与原因，不改变资源记录、依赖关系、分块会话、成品内容或分页游标。

### 读取状态：`GET /resources/{id}/lifecycle`

成功返回 HTTP 200，响应体为紧凑 UTF-8 JSON，键序固定（`id`、`state`、`reason`）并以换行结束。首次读取时状态为 `staged`、原因为 `null`：

```json
{"id":"<资源 id>","state":"staged","reason":null}
```

状态集合固定为 `staged`、`released`、`withdrawn`、`quarantined`，**状态名称区分大小写**。

### 提交目标状态：`POST /resources/{id}/lifecycle`

请求体必须是 JSON 对象，只允许以下两个字段：

| 字段 | 类型 | 是否必填 | 说明 |
| --- | --- | --- | --- |
| `state` | string | 是 | `staged`、`released`、`withdrawn`、`quarantined` 之一，区分大小写 |
| `reason` | string | 否 | 非空业务原因，最长 1024 个 Unicode 码点 |

隔离或撤回（目标状态为 `quarantined` 或 `withdrawn`）必须提供非空 `reason`；其他请求可省略 `reason`（响应中原因为 `null`）。成功（含幂等重试）返回 HTTP 200：

```bash
curl -s -X POST http://127.0.0.1:8000/resources/$ID/lifecycle \
  -H 'Content-Type: application/json' \
  -d '{"state":"released"}'
```

```json
{"id":"<资源 id>","state":"released","reason":null}
```

### 状态跳转规则

- `staged → released`（晋级）：只有在**成品已组装完成**且**全部可达依赖状态正常**（没有被隔离或撤回）时才允许。
  - 成品尚未组装完成时返回 HTTP 409（错误码 `content_not_complete`）。
  - 任一可达依赖处于 `withdrawn` 或 `quarantined` 时返回 HTTP 409（错误码 `dependency_blocked`）。
- `staged → quarantined`（隔离）：允许，须给非空原因。
- `released → withdrawn`（撤回）、`released → quarantined`（隔离）：允许，须给非空原因。
- `withdrawn → staged`、`quarantined → staged`：允许，无需原因；之后若要 released 仍须重新通过晋级检查（即“先回 staged 再检查”）。`quarantined` 不得直达 `released`。
- 其余跳转均为非法跳转，返回 HTTP 409（错误码 `invalid_state_transition`），状态保持不变。

### 幂等与原因

- 以**相同状态和相同原因**再次提交返回 HTTP 200，响应不变，且**不新增任何记录**。
- 已处于目标状态但原因不同（包括给默认无原因的状态补填原因）视为非法跳转，返回 HTTP 409（错误码 `invalid_state_transition`），状态与原因都不变。
- 原因一经记录不可修改；要变更状态请走允许的跳转。

### 生命周期接口的错误

下列情况都返回 HTTP 400（错误码 `invalid_request`），且不改变任何状态：

- 请求体缺失、不是合法 UTF-8 JSON、顶层不是 JSON 对象，或出现未知字段；
- 路径标识为空或含 `/`、`\\`，或携带任意查询参数；
- `state` 缺失、不是字符串、为空或不在四个合法状态之内（注意区分大小写，如 `"Staged"` 非法）；
- `reason` 类型错误、为空或超过 1024 个 Unicode 码点；隔离或撤回缺少原因。

标识格式合法但资源不存在，返回 HTTP 404（错误码 `resource_not_found`）。`GET`、`POST` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET, POST`）。

任何失败都不会新增或修改资源、依赖关系、分块、成品内容或游标；资源响应结构、启动方式和内存边界保持不变。

## 安全告警（漏洞）

可以对已登记的资源逐条登记安全告警。告警只保存在当前进程内存中，服务停止或重启后随资源一起清空，不会写入任何文件，也不承诺跨进程同步。告警按提交顺序保存；批量登记、更新、删除与并发处理不在当前范围内。

### 登记告警：`POST /resources/{id}/vulnerabilities`

请求体必须是一个完整的 JSON 对象，字段如下：

| 字段 | 类型 | 是否必填 | 说明 |
| --- | --- | --- | --- |
| `advisory` | string | 是 | 公告编号，非空，最多 256 个 Unicode 码点 |
| `component` | string | 是 | 受影响组件，非空，最多 256 个 Unicode 码点 |
| `severity` | string | 是 | `critical`、`high`、`medium`、`low` 之一，比较时忽略大小写，按小写存储与输出 |
| `summary` | string | 是 | 摘要，非空，最多 2048 个 Unicode 码点 |
| `fixed_version` | string | 否 | 修复版本；提供时必须非空且最多 256 个 Unicode 码点，省略时为 `null` |

不允许额外未知字段。成功返回 HTTP 201，响应体为紧凑 UTF-8 JSON，键序固定（`id`、`advisory`、`component`、`severity`、`summary`、`fixed_version`）并以换行结束：

```bash
curl -s -X POST http://127.0.0.1:8000/resources/$ID/vulnerabilities \
  -H 'Content-Type: application/json' \
  -d '{"advisory":"CVE-2026-0001","component":"openssl","severity":"HIGH","summary":"存在缓冲区溢出","fixed_version":"3.0.9"}'
```

```json
{"id":"…","advisory":"CVE-2026-0001","component":"openssl","severity":"high","summary":"存在缓冲区溢出","fixed_version":"3.0.9"}
```

同一资源下公告编号与组件均相同的重复登记返回 HTTP 409（错误码 `duplicate_vulnerability`），原告警保持不变；公告编号或组件任一不同即视为不同告警。告警的 `severity`、`summary`、`fixed_version` 不参与去重。

### 查询告警：`GET /resources/{id}/vulnerabilities`

不带查询参数时，按提交顺序返回该资源的全部告警，空集合也是成功响应：

```json
{"vulnerabilities":[]}
```

可使用 `severity` 查询参数按级别筛选，取值为 `critical`、`high`、`medium`、`low`，比较忽略大小写；筛选结果仍保持提交顺序，且不重复。例如：

```bash
curl -s 'http://127.0.0.1:8000/resources/$ID/vulnerabilities?severity=HIGH'
```

### 告警接口的错误

下列情况都返回 HTTP 400（错误码 `invalid_request`），且不新增任何告警，也不改变其他任何状态：

- 请求体缺失、不是合法 UTF-8、无法解码为 JSON，或顶层不是 JSON 对象；
- 缺少必填字段、字段类型错误、字段为空、出现未知字段，或 `severity` 不是四个合法级别之一；
- `advisory`、`component` 超过 256 个 Unicode 码点，`summary` 超过 2048 个，或 `fixed_version` 提供但为空、超过 256 个码点；
- 路径标识为空或含 `/`、`\\`；
- POST 请求携带任意查询参数；GET 请求出现未知或重复的查询参数，或 `severity` 为空、不是合法级别。

路径标识格式合法但资源不存在时，POST 与 GET 都返回 HTTP 404（错误码 `resource_not_found`），且不改变任何告警。对 `/resources/{id}/vulnerabilities` 使用 `GET`、`POST` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET, POST`）。

任何失败都不会修改资源、依赖、分块、成品、生命周期状态或列表游标；重复的非法请求同样不能产生隐藏记录。

## SBOM 文档与许可证

可以为已登记的资源各登记一份 SBOM 文档和一份许可证声明。SBOM 文档与许可证都只保存在当前进程内存中，服务停止或重启后随资源一起清空，不会写入任何文件，也不承诺跨进程同步。每个资源至多保留一份 SBOM 与一份许可证。

### 登记 SBOM：`POST /resources/{id}/sbom`

请求体必须是一个完整的 JSON 对象，且只允许以下两个字段：

| 字段 | 类型 | 是否必填 | 说明 |
| --- | --- | --- | --- |
| `format` | string | 是 | 文档格式，只允许 `spdx` 或 `cyclonedx`，区分大小写 |
| `components` | array | 是 | 组件数组，可以为空数组；元素按提交顺序保留 |

数组元素必须是 JSON 对象，且只包含 `name`、`version`、`digest` 三个字段，三者均为非空字符串；`digest` 必须是 64 位十六进制值，接受大小写混合，响应中统一使用小写形式。不允许额外未知字段。

首次登记成功返回 HTTP 201，响应体为紧凑 UTF-8 JSON，键序固定（`id`、`format`、`components`）并以换行结束：

```bash
curl -s -X POST http://127.0.0.1:8000/resources/$ID/sbom \
  -H 'Content-Type: application/json' \
  -d '{"format":"spdx","components":[{"name":"openssl","version":"3.0.8","digest":"A1B2C3D4E5F60000000000000000000000000000000000000000000000000000"}]}'
```

```json
{"id":"<资源 id>","format":"spdx","components":[{"name":"openssl","version":"3.0.8","digest":"a1b2c3d4e5f60000000000000000000000000000000000000000000000000000"}]}
```

幂等与冲突：

- 组件按提交顺序保留；同一文档内 `name`、`version`、`digest` 三元组重复时返回 HTTP 409（错误码 `duplicate_component`），不写入任何文档。三元组任一不同即视为不同组件。
- 相同文档（格式与规范化后的全部组件完全一致）再次提交视为幂等，返回 HTTP 200，回显内容与首次登记相同，且不生成第二份记录。
- 已有文档时提交任何不同内容（格式不同、组件增减或任一组件字段不同）返回 HTTP 409（错误码 `sbom_conflict`），原文档保持不变。

### 查询 SBOM：`GET /resources/{id}/sbom`

返回该资源唯一一份 SBOM 文档，形状与登记响应相同，仍是 HTTP 200。资源存在但从未登记 SBOM 时返回 HTTP 404（错误码 `sbom_not_found`）。

### 登记许可证：`POST /resources/{id}/license`

请求体必须是 JSON 对象，字段如下：

| 字段 | 类型 | 是否必填 | 说明 |
| --- | --- | --- | --- |
| `spdx_id` | string | 是 | 非空 SPDX 许可证标识，原样回显 |
| `source` | string | 否 | 非空来源描述；省略时为 `null`，有值时原样回显 |

不允许额外未知字段，也不接受空值。首次登记成功返回 HTTP 201，响应体为紧凑 UTF-8 JSON，键序固定（`id`、`spdx_id`、`source`）并以换行结束：

```bash
curl -s -X POST http://127.0.0.1:8000/resources/$ID/license \
  -H 'Content-Type: application/json' \
  -d '{"spdx_id":"Apache-2.0","source":"https://example.invalid/LICENSE"}'
```

```json
{"id":"<资源 id>","spdx_id":"Apache-2.0","source":"https://example.invalid/LICENSE"}
```

相同内容（`spdx_id` 与 `source` 均一致，省略与省略、`null` 与 `null` 视为相同）重提返回 HTTP 200；任一不同返回 HTTP 409（错误码 `license_conflict`），原声明保持不变。

### 查询许可证：`GET /resources/{id}/license`

返回该资源唯一一份许可证声明，形状与登记响应相同。资源存在但从未登记许可证时返回 HTTP 404（错误码 `license_not_found`）。

### SBOM 与许可证接口的错误

下列情况都返回 HTTP 400（错误码 `invalid_request`），且不写入或修改任何文档、许可证或其他状态：

- 请求体缺失、不是合法 UTF-8、无法解码为 JSON，或顶层不是 JSON 对象；
- SBOM 请求缺少 `format` 或 `components`、出现未知字段、`format` 不是 `spdx`/`cyclonedx`、`components` 不是数组；
- 组件元素不是对象、缺少 `name`/`version`/`digest`、任一字段不是非空字符串、出现未知字段，或 `digest` 不是 64 位十六进制值；
- 许可证请求缺少 `spdx_id`、`spdx_id` 为空或不是字符串、`source` 为空或不是字符串，或出现未知字段；
- 路径标识为空或含 `/`、`\\`；两个接口的 GET、POST 请求携带任意查询参数。

路径标识格式合法但资源不存在时，POST 与 GET 都返回 HTTP 404（错误码 `resource_not_found`）；资源存在但对应文档或声明缺失时分别返回 404（`sbom_not_found`、`license_not_found`）。对这两个路径使用 `GET`、`POST` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET, POST`）。

任何失败都不会修改资源、依赖、分块、成品、生命周期状态、安全告警、SBOM 文档或许可证；SBOM 与许可证仅存于当前进程内存，停止或重启即清空，不生成任何文件。

## 构建来源证明（provenance）

可以为已登记的资源登记一份构建来源证明，描述该资源的一次构建。证明只保存在当前进程内存中，服务停止或重启后随资源一起清空，不会写入任何文件；当前版本不校验签名，也不改变任何晋级条件。每个资源至多保留一份证明。

### 登记证明：`POST /resources/{id}/provenance`

请求体必须是一个完整的 JSON 对象，且只允许以下四个字段：

| 字段 | 类型 | 是否必填 | 说明 |
| --- | --- | --- | --- |
| `builder` | string | 是 | 构建者，非空文本，最多 256 个 Unicode 码点 |
| `build_number` | string | 是 | 构建编号，非空文本，最多 256 个 Unicode 码点 |
| `source_digest` | string | 是 | 来源摘要，必须是 64 位十六进制值；接受大小写混合，统一按小写保存与返回 |
| `materials` | array | 是 | 材料数组，可以为空数组；元素按提交顺序稳定保留 |

数组元素必须是 JSON 对象，且只包含 `name`、`digest` 两个字段，二者均必填：`name` 为非空文本且不超过 256 个 Unicode 码点；`digest` 必须是 64 位十六进制文本，接受大小写混合，响应中统一使用小写形式。材料不得重复：同一证明中 `name` 与规范化后的 `digest` 完全相同的材料出现多次时返回 HTTP 400（错误码 `invalid_request`），不写入任何证明。不允许缺字段、带未知字段或使用错误类型。

同一资源首次登记成功返回 HTTP 201，响应体为紧凑 UTF-8 JSON，键序固定（`id`、`builder`、`build_number`、`source_digest`、`materials`）并以换行结束：

```bash
curl -s -X POST http://127.0.0.1:8000/resources/$ID/provenance \
  -H 'Content-Type: application/json' \
  -d '{"builder":"ci-bot","build_number":"build-2026-09-24-001","source_digest":"A1B2C3D4E5F60000000000000000000000000000000000000000000000000000","materials":[{"name":"openssl","digest":"B2C3D4E5F6000000000000000000000000000000000000000000000000000000"}]}'
```

```json
{"id":"…","builder":"ci-bot","build_number":"build-2026-09-24-001","source_digest":"a1b2c3d4e5f60000000000000000000000000000000000000000000000000000","materials":[{"name":"openssl","digest":"b2c3d4e5f6000000000000000000000000000000000000000000000000000000"}]}
```

幂等与冲突：

- 规范化后的内容完全相同（构建者、构建编号、小写来源摘要及全部材料的名称与小写摘要一致，材料顺序也一致）再次登记视为幂等，返回 HTTP 200，回显内容与首次登记相同，且不生成第二份记录。
- 已有不同证明时（任一字段不同，包括材料顺序或数量不同）返回 HTTP 409（错误码 `provenance_conflict`），原记录不被覆盖。

### 查询证明：`GET /resources/{id}/provenance`

返回该资源唯一一份构建来源证明，形状与登记响应相同，仍是 HTTP 200。资源存在但从未登记证明时返回 HTTP 404（错误码 `provenance_not_found`）。

### 证明接口的错误

下列情况都返回 HTTP 400（错误码 `invalid_request`），且不写入或修改任何证明或其他状态：

- 请求体缺失、不是合法 UTF-8、无法解码为 JSON，或顶层不是 JSON 对象；
- 缺少 `builder`、`build_number`、`source_digest`、`materials` 中任一字段，或出现未知字段；
- `builder`、`build_number` 不是字符串、为空或超过 256 个 Unicode 码点；
- `source_digest` 不是 64 位十六进制文本；
- `materials` 不是数组；材料元素不是对象、缺少 `name`/`digest`、字段类型错误、为空、超长、摘要不是 64 位十六进制文本、出现未知字段，或材料重复；
- 路径标识为空或含 `/`、`\\`；GET、POST 请求携带任意查询参数。

路径标识格式合法但资源不存在时，POST 与 GET 都返回 HTTP 404（错误码 `resource_not_found`）；资源存在但尚未登记证明时 GET 返回 404（`provenance_not_found`）。对该路径使用 `GET`、`POST` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET, POST`）。

任何失败都不会写入证明，也不会修改资源、依赖、内容、游标、生命周期状态、安全告警、SBOM 文档或许可证；证明仅存于当前进程内存，停止或重启即清空，本次不校验签名也不改变晋级条件。

## 准入策略与准入评估

可以为已登记的资源登记一份准入策略，并据此对该资源执行一次只读的准入评估。策略与评估结果都只保存在当前进程内存中（评估结果不落任何记录），服务停止或重启后随资源一起清空，不会写入任何文件；当前版本不校验签名，也不改变任何晋级条件。每个资源至多保留一份策略。

### 登记策略：`POST /resources/{id}/policies`

请求体必须是一个完整的 JSON 对象，且只允许以下四个字段：

| 字段 | 类型 | 是否必填 | 说明 |
| --- | --- | --- | --- |
| `name` | string | 是 | 非空策略名称，最多 256 个 Unicode 码点，原样回显 |
| `evidence_requirements` | array | 是 | 证据要求，元素只允许 `sbom`、`license`、`provenance`，区分大小写；可以为空数组，且不得重复 |
| `license_allowlist` | array | 是 | 允许的 SPDX 许可证标识字符串数组，元素为非空字符串且不得重复；可以为空数组，空表示不做许可证限制；原样回显 |
| `max_severity` | string | 是 | 级别上限，`critical`、`high`、`medium`、`low` 之一，比较时忽略大小写，按小写保存与输出 |

首次登记成功返回 HTTP 201，响应体为紧凑 UTF-8 JSON，键序固定（`id`、`name`、`evidence_requirements`、`license_allowlist`、`max_severity`）并以换行结束：

```bash
curl -s -X POST http://127.0.0.1:8000/resources/$ID/policies \
  -H 'Content-Type: application/json' \
  -d '{"name":"release-gate","evidence_requirements":["sbom","license","provenance"],"license_allowlist":["Apache-2.0","MIT"],"max_severity":"HIGH"}'
```

```json
{"id":"…","name":"release-gate","evidence_requirements":["sbom","license","provenance"],"license_allowlist":["Apache-2.0","MIT"],"max_severity":"high"}
```

幂等与冲突：

- 相同内容（四个字段完全一致，数组内容与顺序也一致）重提视为幂等，返回 HTTP 200，回显内容与首次登记相同，且不生成第二份记录。
- 已有策略时提交任何不同内容（包括名称、证据项或许可证项的增减或顺序变化、上限不同）返回 HTTP 409（错误码 `policy_conflict`），原策略保持不变。

### 查询策略：`GET /resources/{id}/policies`

返回该资源唯一一份策略，形状与登记响应相同，仍是 HTTP 200。资源存在但从未登记策略时返回 HTTP 404（错误码 `policy_not_found`）。

### 准入评估：`POST /resources/{id}/admission`

对资源执行一次只读判定，**不接受请求体**（声明非空 `Content-Length` 即返回 400），也不接受查询参数。服务按该资源的策略读取其生命周期状态、SBOM、许可证声明、构建证明与全部安全告警，但不写入或修改任何状态。

成功返回 HTTP 200，响应体为紧凑 UTF-8 JSON，键序固定（`id`、`allowed`、`reasons`）并以换行结束：

```bash
curl -s -X POST http://127.0.0.1:8000/resources/$ID/admission
```

```json
{"id":"…","allowed":true,"reasons":[]}
```

| 字段 | 说明 |
| --- | --- |
| `id` | 被评估资源的标识 |
| `allowed` | 全部条件通过为 `true`；命中任一拒绝原因为 `false` |
| `reasons` | 命中的稳定原因代码数组，按下方顺序排列；全部通过时为空数组 `[]` |

判定规则与原因代码，按固定优先级（状态 → 证据 → 许可证 → 严重度）排列：

1. **状态**：资源当前生命周期状态为 `withdrawn` 或 `quarantined` 时直接拒绝，原因代码为 `state_blocked`，且**不再检查**任何其他条件（此时 `reasons` 只含这一项）。
2. **证据**：策略要求但资源尚未登记的证据逐项拒绝，原因代码分别为 `no_sbom`、`no_license`、`no_provenance`，按此顺序输出；未要求的证据不检查。
3. **许可证**：`license_allowlist` 非空，而资源登记的许可证 SPDX 标识不在清单中（或资源未登记许可证）时拒绝，原因代码为 `license_denied`；清单为空时不检查许可证。
4. **严重度**：资源存在严重度**高于**上限（等于上限不算超限）的安全告警时拒绝，原因代码为 `severity_exceeded`，比较忽略大小写。

未命中状态阻断时，证据、许可证、严重度三组条件都会被评估；命中多条时组内与组间均按上面的顺序输出，例如：

```json
{"id":"…","allowed":false,"reasons":["no_sbom","no_license","no_provenance","license_denied","severity_exceeded"]}
```

### 策略与评估接口的错误

下列情况都返回 HTTP 400（错误码 `invalid_request`），且不写入或修改任何策略或其他状态：

- 请求体缺失、不是合法 UTF-8、无法解码为 JSON，或顶层不是 JSON 对象；
- 缺少四个字段中任一项、字段为空值（空名称、空证据项或许可证项）、出现未知字段；
- `name` 不是字符串或超过 256 个 Unicode 码点；
- `evidence_requirements` 或 `license_allowlist` 不是数组、元素类型错误、证据项不是 `sbom`/`license`/`provenance`，或数组内出现重复值；
- `max_severity` 不是四个合法级别之一；
- 路径标识为空或含 `/`、`\\`；策略登记、查询请求携带任意查询参数；
- 准入评估请求携带请求体或任意查询参数。

路径标识格式合法但资源不存在时，三个接口都返回 HTTP 404（错误码 `resource_not_found`）；资源存在但尚未登记策略时，策略查询与准入评估返回 HTTP 404（错误码 `policy_not_found`）。对 `/resources/{id}/policies` 使用 `GET`、`POST` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET, POST`）；对 `/resources/{id}/admission` 使用 `POST` 之外的方法返回 HTTP 405（`Allow: POST`）。

任何失败都不会写入策略或评估结果，也不会修改资源、依赖、内容、游标、生命周期状态、安全告警、SBOM 文档、许可证声明或构建来源证明；策略仅存于当前进程内存，停止或重启即清空，本次不校验签名也不改变晋级条件。

## 风险评分

可以对已登记的资源即时计算一次风险评分。评分只读取该资源当前的安全告警、SBOM、许可证声明、构建来源证明、生命周期状态与准入策略，**不写入或修改任何状态**，也不留下任何评分记录；重启后随全部输入一起清空，不写入任何文件。

### 查询风险评分：`GET /resources/{id}/risk`

成功返回 HTTP 200，响应体为紧凑 UTF-8 JSON，键序固定（`id`、`score`、`level`）并以换行结束：

```bash
curl -s "http://127.0.0.1:8000/resources/$ID/risk"
```

```json
{"id":"<资源 id>","score":45,"level":"medium"}
```

| 字段 | 说明 |
| --- | --- |
| `id` | 被评分资源的标识 |
| `score` | 0 到 100 的整数风险分，按下方规则累加并封顶到 100 |
| `level` | 风险等级：`score` 低于 25 为 `low`，低于 50 为 `medium`，低于 75 为 `high`，其余为 `critical` |

计分规则：

- 每条安全告警按严重度加分：`critical` 加 40 分、`high` 加 25 分、`medium` 加 10 分、`low` 加 5 分，比较时忽略大小写；
- SBOM 文档、许可证声明、构建来源证明每缺一份加 5 分；
- 资源处于 `withdrawn` 或 `quarantined` 状态时再加 20 分；
- 资源策略的 `license_allowlist` 非空，而资源未登记许可证或登记的 SPDX 标识不在清单内时加 10 分；清单为空或未登记策略时不加；
- 总分封顶到 100。

### 风险评分接口的错误

- 路径标识为空或含 `/`、`\\`，或携带任意查询参数，返回 HTTP 400（错误码 `invalid_request`），不执行任何计算。
- 标识格式合法但资源不存在，返回 HTTP 404（错误码 `resource_not_found`），状态不变。
- `GET` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET`）。

## 通知登记

可以为已登记的资源逐条登记通知记录。每次提交独立生成一条记录，各条之间互不影响：不去重、不更新、不删除。通知只保存在当前进程内存中，服务停止或重启后随资源一起清空，不会写入任何文件。

### 登记通知：`POST /resources/{id}/notifications`

请求体必须是一个完整的 JSON 对象，且只允许以下三个字段，三者均为必填的非空字符串：

| 字段 | 类型 | 是否必填 | 说明 |
| --- | --- | --- | --- |
| `channel` | string | 是 | 通知渠道，非空，最多 64 个 Unicode 码点 |
| `target` | string | 是 | 通知目标，非空，最多 256 个 Unicode 码点 |
| `message` | string | 是 | 通知内容，非空，最多 2048 个 Unicode 码点 |

不允许额外未知字段。成功返回 HTTP 201，响应体为紧凑 UTF-8 JSON，键序固定（`id`、`channel`、`target`、`message`）并以换行结束，其中 `id` 是服务生成的记录标识：

```bash
curl -s -X POST http://127.0.0.1:8000/resources/$ID/notifications \
  -H 'Content-Type: application/json' \
  -d '{"channel":"email","target":"alerts@example.invalid","message":"risk level changed"}'
```

```json
{"id":"…","channel":"email","target":"alerts@example.invalid","message":"risk level changed"}
```

完全相同的重复提交也会各自生成新记录，返回各自的 201 与不同的 `id`。

### 查询通知：`GET /resources/{id}/notifications`

按提交顺序返回该资源的全部通知记录，不去重、不改删；空集合也是成功响应：

```json
{"notifications":[]}
```

### 通知接口的错误

下列情况都返回 HTTP 400（错误码 `invalid_request`），且不写入任何通知记录：

- 请求体缺失、不是合法 UTF-8、无法解码为 JSON，或顶层不是 JSON 对象；
- 缺少 `channel`、`target`、`message` 中任一字段，或出现未知字段；
- 任一字段不是字符串、为空，或超过各自的长度上限（64、256、2048 个 Unicode 码点）；
- 路径标识为空或含 `/`、`\\`；GET、POST 请求携带任意查询参数。

路径标识格式合法但资源不存在时，POST 与 GET 都返回 HTTP 404（错误码 `resource_not_found`），且不改变任何状态。对 `/resources/{id}/notifications` 使用 `GET`、`POST` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET, POST`）。

任何失败都不会写入通知，也不会修改资源、依赖、内容、游标、生命周期状态、安全告警、SBOM 文档、许可证声明、构建来源证明或准入策略；通知仅存于当前进程内存，停止或重启即清空，不生成任何文件。

## 镜像层缓存

服务在全局 `/cache` 路径下提供镜像层缓存，不挂在单个资源上。缓存条目与命中、未命中计数只保存在当前进程内存中，服务停止或重启后全部清空，不会写入任何文件。总字节配额由启动参数 `--cache-quota` 指定（缺省 `1048576`）。

### 写入缓存层：`POST /cache/layers/{digest}`

- 路径 `{digest}` 必须是 64 位十六进制摘要（接受大小写混合，按小写存储）；不是时返回 HTTP 400（错误码 `invalid_request`），且不读取请求体。
- 请求体是按 `Content-Length` 声明长度读取的原始字节流，`Content-Type` 必须为 `application/octet-stream`（大小写无关，不接受参数）；空字节流（`Content-Length: 0`）是合法内容。
- 服务对收到的字节计算 SHA-256，与路径摘要逐字比较，一致且配额允许时缓存该层。

成功返回 HTTP 201，响应体为紧凑 UTF-8 JSON，键序固定（`digest`、`size`、`entries`）并以换行结束：

```bash
curl -s -X POST "http://127.0.0.1:8000/cache/layers/$DIGEST" \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @layer.bin
```

```json
{"digest":"<层摘要>","size":1234,"entries":1}
```

| 字段 | 说明 |
| --- | --- |
| `digest` | 缓存层的 64 位小写十六进制 SHA-256 摘要 |
| `size` | 本次缓存的字节数 |
| `entries` | 当前缓存中的条目总数 |

幂等与冲突：

- 相同摘要以**完全相同的字节**重复提交返回 HTTP 200，响应形状与 201 相同，缓存与计数保持不变（幂等重试）。
- 内容摘要与路径摘要不一致返回 HTTP 409（错误码 `digest_mismatch`），不写入任何缓存条目。
- 同摘要已缓存不同字节时返回 HTTP 409（错误码 `cache_conflict`），原条目不被覆盖。
- 写入会使已用字节超过配额时返回 HTTP 409（错误码 `cache_quota_exceeded`），缓存保持原样。

### 读取缓存层：`GET /cache/layers/{digest}`

- 命中时返回 HTTP 200，响应体**只包含缓存的原始字节**（无 JSON 包装、无末尾换行），`Content-Type: application/octet-stream`，`Content-Length` 为准确字节数，并累计一次命中。
- 摘要未缓存时返回 HTTP 404（错误码 `cache_miss`），并累计一次未命中。
- 路径摘要不是 64 位十六进制时返回 HTTP 400（错误码 `invalid_request`），不计入命中或未命中。

```bash
curl -s "http://127.0.0.1:8000/cache/layers/$DIGEST" --output layer.bin
```

### 查询缓存状态：`GET /cache/status`

只读报告缓存状态，不改变任何条目或计数，可安全重复调用。成功返回 HTTP 200，响应体为紧凑 UTF-8 JSON，键序固定（`entries`、`used_bytes`、`quota`、`hits`、`misses`）并以换行结束：

```json
{"entries":1,"used_bytes":1234,"quota":1048576,"hits":2,"misses":1}
```

| 字段 | 说明 |
| --- | --- |
| `entries` | 当前缓存的条目数 |
| `used_bytes` | 当前已用字节数 |
| `quota` | 启动时指定的总字节配额 |
| `hits` | 累计读取命中次数 |
| `misses` | 累计读取未命中次数 |

### 缓存接口的错误

下列情况都返回 HTTP 400（错误码 `invalid_request`），且不改变缓存内容、用量或计数：

- 路径摘要不是 64 位十六进制字符串；
- 请求携带任意查询参数；
- `Content-Type` 不是 `application/octet-stream`；
- 缺少 `Content-Length`、其值不是非负十进制整数，或实际字节数不足声明长度。

对 `/cache/layers/{digest}` 使用 `GET`、`POST` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET, POST`）；对 `/cache/status` 使用 `GET` 之外的方法返回 HTTP 405（`Allow: GET`）。方法错误同样不改变任何缓存状态。

## 运行测试

```bash
python -m unittest discover -s tests -v
```

## 开发边界

- 新增接口必须在公开文档中说明启动方式、请求和响应行为。
- 持久化数据和生成文件不得提交到 Git。
- 不得把密钥、访问令牌、私有验证脚本或控制系统资料写入仓库。
- 对已有公开接口的更改应保持向后兼容，除非任务明确要求破坏性升级。
- 当前公开业务接口为健康检查、上述资源登记/查询接口、资源依赖关系登记、依赖拓扑查询与影响分析接口、资源内容校验接口、分块上传、组装、分块上传会话状态查询与成品读取接口，资源生命周期状态读取与提交接口，安全告警（漏洞）的登记与查询接口，SBOM 文档与许可证声明的登记与查询接口，构建来源证明（provenance）的登记与查询接口，准入策略的登记与查询接口和只读准入评估接口，按资源即时计算的风险评分接口，通知记录的登记与查询接口，以及全局镜像层缓存的写入、读取与状态查询接口；资源、依赖、分块会话、成品内容、生命周期状态、安全告警、SBOM 文档、许可证声明、构建来源证明、准入策略、通知记录与缓存条目及计数均仅存于进程内存，准入评估结果与风险评分均即时计算、不落记录、不承诺跨进程或重启后的保存。
- 分块能力明确不承诺以下行为：重启后的断点续传（重启清空全部会话与成品）、并发上传的加锁与顺序保证、以及跨资源的批量上传或批量组装。每个分块请求独立校验，冲突时以 409 拒绝且不覆盖既有字节。

