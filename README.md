# 数字资源供应链与溯源平台

这是一个面向代码、AI 模型、数据集和构建产物的后端服务基线。当前版本提供可运行的 HTTP 服务、健康检查、进程内的资源登记、查询与按标识注销（连带清理该资源名下的全部派生记录）、资源之间的依赖关系登记、拓扑查询与影响分析接口、按资源标识提交原始字节的内容校验接口、内容寻址的分块存储、组装与成品读取接口、分块上传会话状态查询接口、资源生命周期状态（晋级、撤回与隔离）接口、按资源即时计算晋级阻塞明细的只读视图接口、按资源登记、查询、就地更新与删除安全告警（漏洞）的接口、把全部告警按公告编号汇总的全局只读视图接口、按公告编号下钻单条公告告警明细的全局只读视图接口、按公告编号下钻其命中组件修复建议的全局只读视图接口、按资源登记与查询 SBOM 文档与许可证声明的接口、按资源登记与查询构建来源证明（provenance）的接口、按资源登记与查询准入策略并执行只读准入评估的接口、全局默认准入策略的登记与查询接口（作用于没有自己策略的资源）、按资源登记、查询与删除安全告警豁免（漏洞例外）并按豁免口径提供只读准入预览的接口、按资源即时计算风险评分的接口、按资源登记与查询通知记录的接口，以及在组件级漏洞关联视图之外、按资源即时计算只读的组件修复建议视图的接口，以及全局镜像层缓存的写入、读取、状态查询、单层删除与清空接口，以及全局镜像源及其签名策略的登记、查询与删除，和按摘要通过镜像源拉取镜像层、对一组层摘要按镜像源批量预取、按镜像源对登记上游发起探活并读取最近一次探活结果的接口，以及把本地资源指向其他仓库资源、登记时即时解析并建立依赖边的跨仓库引用接口，以及按资源登记、查询内容签名并对登记签名执行只读验签的接口。

## 环境

- Python 3.11 或更高版本
- 当前基线没有第三方运行依赖

## 启动服务

在仓库根目录执行：

```bash
python -m provenance_api --host 127.0.0.1 --port 8000
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

镜像层缓存的字节配额由启动参数 `--cache-quota` 指定，单位字节，缺省为 `1048576`：

```bash
python -m provenance_api --host 127.0.0.1 --port 8000 --cache-quota 1048576
```

取值必须是十进制正整数；非法取值（如 `0`、负数、小数、非数字或带前导零的写法）会拒绝启动并输出用法说明。

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

### 注销单个资源：`DELETE /resources/{id}`

按标识注销单条资源。请求不带请求体，也不接受任何查询参数；标识为空或含路径分隔符（`/`、`\\`）、请求声明了非空或非法的请求体、或携带任意查询参数时，都返回 HTTP 400（错误码 `invalid_request`），且不读取或改动任何业务数据。标识格式合法但资源不存在（包括此前已注销）时返回 HTTP 404（错误码 `resource_not_found`）。

成功时返回 HTTP 200，响应体回显被删资源的完整登记内容，紧凑 JSON 以换行结束：

```bash
curl -s -X DELETE http://127.0.0.1:8000/resources/<id>
```

```json
{"id":"…","name":"model-a","category":"model","digest":"a1b2c3d4e5f60000000000000000000000000000000000000000000000000000","source":"https://example.invalid/model-a"}
```

注销会连带清掉该资源名下的告警、豁免、SBOM、许可证、构建证明、策略、签名与通知；分块上传会话与已组装的成品字节随之作废，此前未完成的上传进度不再可查；生命周期状态一并移除，之后同名新登记的资源回到默认的暂存状态，且不继承旧状态。指向该资源的依赖边与它自己发起的依赖边都随之消失，拓扑与影响分析不再出现这些边；由该资源登记的跨仓库引用记录一并移除，引用解析生成的远端本地资源保留不动。全局公告汇总、组件视图、准入预览与风险评分立即按剩余告警重算，不再计入被删数据。此前签发的列表游标继续可用，但翻页与筛选结果都不再包含被注销的资源。

注销只影响被选中的资源：其他资源的记录、缓存条目与镜像源一律不动。同一标识注销后不再复用，后续新登记的资源一律获得新的服务生成标识。该路径的 `Allow` 头为 `DELETE, GET`；其他未声明方法返回 HTTP 405（错误码 `method_not_allowed`），失败请求不改动任何既有状态。

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

### 解除依赖：`DELETE /resources/{id}/dependencies/{dependency_id}`

解除路径中起点资源（`resource_id`）到末段被依赖资源（`dependency_id`）的**这一条直接依赖边**，只接受 `DELETE` 方法。成功返回 HTTP 200，响应体按登记响应的键序回显这条关系，紧凑 JSON 并以单个换行结束：

```bash
curl -s -X DELETE http://127.0.0.1:8000/resources/$A/dependencies/$B
```

```json
{"resource_id":"<资源 A 的 id>","dependency_id":"<资源 B 的 id>"}
```

- 删除只作用于图上这一条直接边：两个资源的登记内容与各条派生记录（告警、豁免、SBOM、溯源、策略、签名、通知、生命周期、内容、跨仓库引用等）一律不动。
- 被删的边不再参与依赖查询、影响分析、晋级阻塞明细与依赖漏洞传导这四类视图；这些视图都按剩余的边即时重算，间接可达却因其他路径保留的关系照常出现。
- 删除之后再登记同一方向的关系会重新建立这条边，按既有 HTTP 201 口径返回。
- 由跨仓库引用建立的边也按同样的直接边移除，引用记录与远端本地资源保持不变；之后重提同一引用仍按既有重复登记拒绝（HTTP 409，`duplicate_reference`），也不会自动把这条边重建回来。
- 路径里任一标识为空或含 `/`、`\\` 时返回 HTTP 400（错误码 `invalid_request`）；请求带任意查询参数或声明了非空请求体，同样返回 HTTP 400。
- 起点资源不存在时返回 HTTP 404（错误码 `resource_not_found`），且不改动任何既有状态。
- 没有这条直接边，或被依赖资源已注销时，返回 HTTP 404（错误码 `dependency_not_found`）；重复删除同一关系也是同样的未找到结果，不会影响其他关系、资源与游标。
- `DELETE` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: DELETE`）。
- 删除成功后资源列表与筛选分页的既有创建顺序不变，此前签发的列表游标继续可用。

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

### 依赖漏洞传导：`GET /resources/{id}/dependency-vulnerability-impact`

把依赖闭包与每个资源的告警记录串起来，按资源标识即时计算，只读、不落记录。返回形状为：

```json
{"impacts":[{"resource_id":"<id>","advisory_count":2,"max_severity":"high"}]}
```

- 起点自身排在首位，其后是沿依赖边可达的全部依赖，顺序与 `GET /resources/{id}/dependencies` 的登记顺序一致，每个资源只出现一次；没有任何依赖时数组里只有起点一条记录，仍是 HTTP 200。
- 每条记录固定三个字段，顺序为 `resource_id`、`advisory_count`、`max_severity`。
- `advisory_count` 是该资源已登记的告警总数，不去重也不合并；`max_severity` 取告警中 `severity` 的最高值，四档从高到低固定为 `critical`、`high`、`medium`、`low`，比较忽略大小写；没有任何告警时 `max_severity` 为 `null`、`advisory_count` 为 `0`。
- 路径标识为空或含 `/`、`\\`，或请求携带任意查询参数，返回 HTTP 400（错误码 `invalid_request`），不读取业务数据；标识合法但资源不存在返回 HTTP 404（错误码 `resource_not_found`）；`GET` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET`）。任何情况下都不改变状态。
- 本次不提供筛选与分页。

### 依赖接口的错误

- 路径标识为空，或含 `/`、`\\`，返回 HTTP 400（错误码 `invalid_request`），不执行任何操作。
- 请求体缺失、不是合法 UTF-8 JSON、顶层不是 JSON 对象、缺少 `dependency_id`、`dependency_id` 不是字符串/为空/含分隔符，或出现未知字段，均返回 HTTP 400（错误码 `invalid_request`）。
- 这些接口不接受查询参数；出现任意查询参数返回 HTTP 400（错误码 `invalid_request`）。
- 起点不存在时，两个查询接口都返回 HTTP 404（错误码 `resource_not_found`），且不改变状态。
- 对 `/resources/{id}/dependencies` 使用 `GET`、`POST` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET, POST`）；对 `/resources/{id}/dependencies/{dependency_id}` 使用 `DELETE` 之外的方法返回 HTTP 405（`Allow: DELETE`）；对 `/resources/{id}/impact` 使用 `GET` 之外的方法返回 HTTP 405（`Allow: GET`）。
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

### 晋级阻塞明细：`GET /resources/{id}/release-blockers`

晋级（`staged → released`）失败时，除了生命周期接口返回的笼统冲突码，还可以通过只读视图查看当前的晋级阻塞明细。该视图按资源标识即时计算，**不接受请求体或查询参数**，不落任何记录，也不改变生命周期、依赖、告警、分块或其他既有状态；既有晋级检查与冲突错误码保持不变。

成功返回 HTTP 200，响应体为紧凑 UTF-8 JSON，顶层键序固定为 `id`、`blocked`、`reasons`、`blockers`、`content_complete` 并以换行结束：

```bash
curl -s "http://127.0.0.1:8000/resources/$ID/release-blockers"
```

成品尚未组装完成、且存在被隔离依赖时：

```json
{"id":"<资源 id>","blocked":true,"reasons":["content_not_complete","dependency_blocked"],"blockers":[{"resource_id":"<依赖 id>","state":"quarantined"}],"content_complete":false}
```

| 字段 | 说明 |
| --- | --- |
| `id` | 被查询资源的标识 |
| `blocked` | 当前无法晋级为 `true`；满足晋级条件、可以晋级时为 `false` |
| `reasons` | 命中的稳定原因代码数组，按既有晋级检查的先后顺序给出；没有命中时为空数组 `[]` |
| `blockers` | 阻塞晋级的可达依赖数组；没有被隔离或撤回的可达依赖时为空数组 `[]` |
| `content_complete` | 成品是否已组装完成 |

原因代码严格按晋级检查的先后顺序排列，两类原因同时存在时全部给出：

1. 成品尚未组装完成时命中 `content_not_complete`，排在最前；
2. 存在被隔离（`quarantined`）或撤回（`withdrawn`）的可达依赖时命中 `dependency_blocked`，跟随其后。

`blockers` 逐项列出状态为 `withdrawn` 或 `quarantined` 的可达依赖（仅直接与间接可达，每个资源只出现一次），每项固定含 `resource_id` 与 `state` 两个字段，顺序与 `GET /resources/{id}/dependencies` 的登记顺序一致；状态正常（`staged`、`released`）的依赖不收。即使成品尚未组装完成，被隔离或撤回的可达依赖仍会照常逐条列出。

可以晋级时 `blocked` 为 `false`，`reasons` 与 `blockers` 均为空数组，`content_complete` 为 `true`：

```json
{"id":"<资源 id>","blocked":false,"reasons":[],"blockers":[],"content_complete":true}
```

错误与边界：

- 路径标识为空或含 `/`、`\\`，或携带任意查询参数，返回 HTTP 400（错误码 `invalid_request`），且不读取业务数据。
- 标识格式合法但资源不存在，返回 HTTP 404（错误码 `resource_not_found`），状态不变。
- `GET` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET`）。
- 该视图即时计算且只读：任何情况下都不落记录，也不改变生命周期、依赖关系、告警等既有状态；数据仍只存进程内存，重启清空。

## 安全告警（漏洞）

可以对已登记的资源逐条登记安全告警，也可以通过批量入口一次提交一组，还可以按告警标识就地更新单条告警，以及按告警标识删除单条告警。告警只保存在当前进程内存中，服务停止或重启后随资源一起清空，不会写入任何文件，也不承诺跨进程同步。告警按提交顺序保存；更新不改变告警标识与提交顺序，并发处理不在当前范围内。

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

### 批量登记告警：`POST /resources/{id}/vulnerabilities/batch`

一次为一组告警提交批量登记。请求体必须是一个完整的 JSON 对象，且只允许 `vulnerabilities` 一个字段：其值是非空数组，单批最多 100 条，每个元素的字段与单条登记完全一致（`advisory`、`component`、`severity`、`summary` 必填，`fixed_version` 可选，不允许未知字段）。

整批按数组顺序视为依次提交。成功时照此顺序生成全部新记录并逐条回显，返回 HTTP 201，响应体顶层是 `vulnerabilities` 记录数组，每条记录的键序与单条登记响应一致，正文仍以单个换行结束：

```bash
curl -s -X POST http://127.0.0.1:8000/resources/$ID/vulnerabilities/batch \
  -H 'Content-Type: application/json' \
  -d '{"vulnerabilities":[{"advisory":"CVE-2026-0001","component":"openssl","severity":"HIGH","summary":"存在缓冲区溢出"},{"advisory":"CVE-2026-0002","component":"zlib","severity":"low","summary":"信息泄露","fixed_version":"1.3.1"}]}'
```

```json
{"vulnerabilities":[{"id":"…","advisory":"CVE-2026-0001","component":"openssl","severity":"high","summary":"存在缓冲区溢出","fixed_version":null},{"id":"…","advisory":"CVE-2026-0002","component":"zlib","severity":"low","summary":"信息泄露","fixed_version":"1.3.1"}]}
```

整批按原子方式提交：任何一条不合法或冲突都不写入任何新告警。数组内部或与既有告警的公告编号、组件组合重复时返回 HTTP 409（错误码 `duplicate_vulnerability`）；任一元素缺字段、类型错误、为空、超长、级别非法或含未知字段时整批返回 HTTP 400（错误码 `invalid_request`），不生成任何记录。请求体缺失、无法解码、顶层不是 JSON 对象、数组为空、数组超过 100 条或请求携带任意查询参数时同样返回 HTTP 400。路径标识为空或含 `/`、`\\` 返回 HTTP 400；标识合法但资源不存在返回 HTTP 404（错误码 `resource_not_found`）。`POST` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: POST`）。

批量登记的告警立刻按既有口径参与单条查询、豁免匹配与准入预览；单条登记与查询的行为不变，全局汇总的计数与排序口径也不变。

### 查询告警：`GET /resources/{id}/vulnerabilities`

不带查询参数时，按提交顺序返回该资源的全部告警，空集合也是成功响应：

```json
{"vulnerabilities":[]}
```

可使用 `severity` 查询参数按级别筛选，取值为 `critical`、`high`、`medium`、`low`，比较忽略大小写；筛选结果仍保持提交顺序，且不重复。例如：

```bash
curl -s 'http://127.0.0.1:8000/resources/$ID/vulnerabilities?severity=HIGH'
```

### 删除单条告警：`DELETE /resources/{id}/vulnerabilities/{vulnerability-id}`

按登记时返回的告警标识移除该资源下的单条告警。只接受 `DELETE` 方法，请求不带请求体，也不接受任何查询参数。成功返回 HTTP 200，并回显被删告警的完整内容，字段与单条登记响应完全一致（`id`、`advisory`、`component`、`severity`、`summary`、`fixed_version`）；正文仍为紧凑 UTF-8 JSON，键序稳定并以单个换行结束：

```bash
curl -s -X DELETE "http://127.0.0.1:8000/resources/$ID/vulnerabilities/$VID"
```

```json
{"id":"…","advisory":"CVE-2026-0001","component":"openssl","severity":"high","summary":"存在缓冲区溢出","fixed_version":"3.0.9"}
```

删除立即在所有即时计算的视图中生效，不留下任何残影：

- 被删记录立刻从该资源的单条查询与严重度筛选结果中消失，不再参与任何统计；其余告警保持原有提交顺序。
- 准入评估（`POST /admission`）与准入预览（`GET /admission-preview`）的超限严重度判定，以及风险评分（`GET /risk`），都不再计入这条告警。
- 组件漏洞关联（`component-risks`）与组件修复建议（`component-fixes`）两处视图同步移除这条告警的关联与计数。
- 全局公告汇总（`GET /advisories`）的计数与资源列表随之收缩；某条公告因此没有任何告警时，该公告直接从汇总中消失。
- 公告明细（`GET /advisories/{advisory}`）的告警明细与 `affected_resources` 同步收缩，被删记录从明细中消失；该公告因此没有任何命中告警时明细的两个数组都为空。
- 公告组件修复建议（`GET /advisories/{advisory}/fixes`）同步移除该组件的命中与计数；某组件因此没有任何命中告警时，该组件直接从结果中消失。
- 依赖漏洞传导（`GET /resources/{id}/dependency-vulnerability-impact`）按闭包内当前告警即时重算，被删告警不再计入各资源的告警总数与最高严重度。

豁免与删除的关系：

- 已登记的告警豁免不随删除撤回，豁免记录保留并仍可在豁免列表中查询，但暂时失去匹配对象；准入预览不再把它计入 `exempted_count`。
- 同一公告编号与组件的告警在该资源上再次登记后，既有豁免立即按原记录重新生效，无需重复登记。

删除释放了该资源下对应公告编号与组件的组合，因此同一组合随后可以再次登记；新登记获得新的告警标识，不会复用旧标识。

### 就地更新单条告警：`PUT /resources/{id}/vulnerabilities/{vulnerability-id}`

按登记时返回的告警标识就地更新该资源下的单条告警。只接受 `PUT` 方法，请求体必须是一个完整的 JSON 对象，字段与单条登记完全一致（`advisory`、`component`、`severity`、`summary` 必填，`fixed_version` 可选，不允许未知字段）。其中公告编号与组件是告警身份，请求体可以给出这两个字段，但必须与现值逐字相同（区分大小写）；与现值任一不同都返回 HTTP 400（错误码 `invalid_request`），告警保持不变。可变更的只有以下三类字段，校验口径与登记时完全一致：

| 字段 | 更新规则 |
| --- | --- |
| `severity` | 仍限 `critical`、`high`、`medium`、`low` 四档，比较忽略大小写，按小写保存与输出 |
| `summary` | 非空，最多 2048 个 Unicode 码点 |
| `fixed_version` | 可省略（置为 `null`）；提供时必须非空且最多 256 个 Unicode 码点 |

成功返回 HTTP 200，回显更新后的完整记录，字段与键序同登记响应（`id`、`advisory`、`component`、`severity`、`summary`、`fixed_version`），紧凑 UTF-8 JSON 并以单个换行结束。告警标识 `id` 与提交位置都不变：

```bash
curl -s -X PUT "http://127.0.0.1:8000/resources/$ID/vulnerabilities/$VID" \
  -H 'Content-Type: application/json' \
  -d '{"advisory":"CVE-2026-0001","component":"openssl","severity":"low","summary":"修复已回填","fixed_version":"3.0.10"}'
```

```json
{"id":"…","advisory":"CVE-2026-0001","component":"openssl","severity":"low","summary":"修复已回填","fixed_version":"3.0.10"}
```

更新立即在所有即时计算的视图中按新值重算：

- 准入评估（`POST /admission`）与准入预览（`GET /admission-preview`）的超限严重度判定按新严重度重新计算；准入预览中豁免的匹配关系与计数不受影响。
- 风险评分（`GET /risk`）按新严重度逐条重新加分。
- 组件修复建议（`component-fixes`）的推荐版本随新修复版本重新取最大值；组件漏洞关联（`component-risks`）展示的严重度同步更新。
- 全局公告汇总（`GET /advisories`）与依赖漏洞传导（`dependency-vulnerability-impact`）的最高严重度按新值更新；汇总的计数、资源列表与各视图的告警条数均保持不变。
- 公告明细（`GET /advisories/{advisory}`）按新值即时重算该条告警的严重度、摘要与修复版本；改严重度后按新级别参与 `severity` 筛选，明细条数与资源列表保持不变。
- 公告组件修复建议（`GET /advisories/{advisory}/fixes`）的推荐版本随新修复版本重新取最大值；改严重度后按新级别参与 `severity` 筛选；告警条数与资源列表保持不变。

已登记豁免仍按公告编号与组件逐字匹配：更新严重度或修复版本（以及摘要）不改变匹配关系，豁免继续对同一条告警生效。

### 告警接口的错误

下列情况都返回 HTTP 400（错误码 `invalid_request`），且不新增任何告警，也不改变其他任何状态：

- 请求体缺失、不是合法 UTF-8、无法解码为 JSON，或顶层不是 JSON 对象；
- 缺少必填字段、字段类型错误、字段为空、出现未知字段，或 `severity` 不是四个合法级别之一；
- `advisory`、`component` 超过 256 个 Unicode 码点，`summary` 超过 2048 个，或 `fixed_version` 提供但为空、超过 256 个码点；
- 路径标识为空或含 `/`、`\\`；
- POST 请求携带任意查询参数；GET 请求出现未知或重复的查询参数，或 `severity` 为空、不是合法级别；
- DELETE 请求的告警标识为空或含 `/`、`\\`，携带任意查询参数，或声明了非空（或非法）的请求体；
- PUT 请求的请求体缺失、不是合法 UTF-8、无法解码为 JSON、顶层不是 JSON 对象、缺少必填字段、出现未知字段、字段类型错误、字段为空、超长或严重度非法；请求体给出的 `advisory`、`component` 与现值任一不同；PUT 请求的告警标识为空或含 `/`、`\\`，或携带任意查询参数。出现上述任一情况都不会留下半条更新。

路径标识格式合法但资源不存在时，POST 与 GET 都返回 HTTP 404（错误码 `resource_not_found`），且不改变任何告警。对 `/resources/{id}/vulnerabilities` 使用 `GET`、`POST` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET, POST`）。

更新单条告警时，告警标识未知、属于其他资源，或此前已经删除，都返回 HTTP 404（错误码 `vulnerability_not_found`），且不改动任何已有记录。资源标识合法但资源不存在仍返回 HTTP 404（错误码 `resource_not_found`）。对 `/resources/{id}/vulnerabilities/{vulnerability-id}` 使用 `PUT` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow` 头只给出 `PUT`）；该路径上既有的 `DELETE` 删除行为保持不变。

任何失败都不会新增、修改或删除任何告警，也不改变豁免、准入与风险等既有状态，更不会修改资源、依赖、分块、成品、生命周期状态或列表游标；重复的非法请求同样不能产生隐藏记录。单条登记、批量登记与查询的既有行为完全不变，校验口径也保持一致。告警数据仍只存进程内存，停止或重启即清空，服务不生成任何文件。

## 全局告警汇总视图

在按资源分别查看告警之外，可以把全部资源的全部告警按公告编号汇总为一个全局视图。该视图即时计算且只读，不落任何记录，也不改变告警、资源、准入、豁免与风险评分的结果；其输入仍只存于当前进程内存，服务停止或重启后随告警一起清空，不写入任何文件。

### 查询汇总：`GET /advisories`

只接受 `GET` 查询，不接受请求体。成功返回 HTTP 200，响应体是紧凑 UTF-8 JSON 数组并以单个换行结束；每条记录固定四个键，顺序为 `advisory`、`affected_resources`、`advisory_count`、`max_severity`：

```bash
curl -s http://127.0.0.1:8000/advisories
```

```json
[{"advisory":"CVE-2026-0001","affected_resources":["<资源 id>","<资源 id>"],"advisory_count":3,"max_severity":"critical"}]
```

| 字段 | 说明 |
| --- | --- |
| `advisory` | 公告编号，原样输出 |
| `affected_resources` | 贡献了该公告告警的资源标识数组；按资源登记顺序排列，每个资源只出现一次，不受告警提交先后影响 |
| `advisory_count` | 该公告下的告警记录总数，不去重也不合并；同一资源贡献的多条记录照常累加 |
| `max_severity` | 该公告全部告警里的最高严重度，四档从高到低固定为 `critical`、`high`、`medium`、`low`，比较忽略大小写，输出为小写 |

公告按首次出现的顺序展开，即按最早那条对应告警的提交先后排列，与资源登记先后无关。例如某公告的第一条告警登记在较晚注册的资源上，它仍排在第一条告警更晚提交的公告之前。没有任何告警时返回空数组 `[]`，同样是成功响应。

#### 按严重度筛选

可使用 `severity` 查询参数只统计命中级别的告警后再分组，取值为 `critical`、`high`、`medium`、`low`，比较忽略大小写：

```bash
curl -s 'http://127.0.0.1:8000/advisories?severity=HIGH'
```

筛选不改变组内排序与计数口径：`affected_resources` 仍按资源登记顺序去重排列，`advisory_count` 只数命中告警，`max_severity` 只在命中告警中取最高，公告的首次出现顺序也按命中告警的最早提交时间重新确定；只贡献了未命中级别的资源不出现在该公告的 `affected_resources` 中。筛选没有命中任何告警时返回空数组 `[]`，是正常响应而不是错误。

### 全局汇总接口的错误

- 请求不接受请求体：声明非空或非法 `Content-Length` 时返回 HTTP 400（错误码 `invalid_request`），不读取业务数据；省略该头或显式声明 `0` 视为空请求体。
- 查询参数只允许 `severity`；出现未知参数或重复参数（含重复 `severity`）返回 HTTP 400（错误码 `invalid_request`）。
- `severity` 值为空或不在四个级别之内时返回 HTTP 400（错误码 `invalid_request`）。
- `GET` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow` 头只给出 `GET`）。
- 错误体沿用既有 JSON 错误形状（`{"error":"…","message":"…"}`）与稳定错误码，紧凑 JSON 并以单个换行结束。

该视图不改变告警登记与查询的既有语义，也不改准入评估、豁免预览、风险评分和组件视图的口径。镜像拉取签名请求头取值非法返回 400 的口径只适用于单摘要拉取这一条链路；批量预取的逐项签名判定不变，多项同时命中只报排在最前的一项。

### 查询单个公告明细：`GET /advisories/{advisory}`

在全局汇总之外，可以按公告编号下钻查看单个公告的告警明细。只接受 `GET`，不接受请求体。公告编号逐字完整匹配：区分大小写、不做空白修剪，请求的编号在响应中原样回显。成功返回 HTTP 200，响应体为紧凑 UTF-8 JSON 并以单个换行结束，顶层键序固定为 `advisory`、`affected_resources`、`alerts`：

```bash
curl -s http://127.0.0.1:8000/advisories/CVE-2026-0001
```

```json
{"advisory":"CVE-2026-0001","affected_resources":["<资源 id>"],"alerts":[{"resource_id":"<资源 id>","id":"<告警 id>","advisory":"CVE-2026-0001","component":"openssl","severity":"high","summary":"…","fixed_version":null}]}
```

| 字段 | 说明 |
| --- | --- |
| `advisory` | 请求的公告编号，原样回显 |
| `affected_resources` | 本次命中的告警所归属的资源标识数组；按资源登记顺序去重，每个资源只出现一次 |
| `alerts` | 命中的告警明细；每条以 `resource_id` 开头，随后按单条登记响应的键序完整回显该条告警 |

明细按资源登记顺序展开，同一资源内保持告警提交顺序，每个资源只出现一次。同样支持 `severity` 查询参数（四档严重度，比较忽略大小写），筛选后只保留命中级别的告警，明细与资源列表随之收缩，排序口径不变；同一筛选条件下命中的计数与最高严重度与全局汇总视图完全一致。公告编号不存在或筛选没有命中任何告警时都返回 HTTP 200，`alerts` 与 `affected_resources` 为空数组，仍属成功响应。该入口即时计算且只读，不落记录，告警更新或删除后立即按新内容重算。

该入口的错误口径与汇总视图一致：公告编号为空、缺失或含路径分隔符，携带未知或重复查询参数，`severity` 为空或非法，或声明了非空请求体，都返回 HTTP 400（错误码 `invalid_request`），且不读取业务数据、不改变任何既有状态；`GET` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow` 头只给出 `GET`）。

### 查询单个公告的组件修复建议：`GET /advisories/{advisory}/fixes`

在公告明细之外，还可以按公告编号下钻该公告命中的组件修复建议。只接受 `GET`，不接受请求体。公告编号逐字完整匹配：区分大小写、不做空白修剪，请求的编号在响应中原样回显。成功返回 HTTP 200，响应体为紧凑 UTF-8 JSON 并以单个换行结束，顶层键序固定为 `advisory`、`fixes`：

```bash
curl -s http://127.0.0.1:8000/advisories/CVE-2026-0001/fixes
```

```json
{"advisory":"CVE-2026-0001","fixes":[{"name":"openssl","affected_resources":["<资源 id>"],"advisory_count":2,"recommended_version":"3.0.10"}]}
```

| 字段 | 说明 |
| --- | --- |
| `advisory` | 请求的公告编号，原样回显 |
| `fixes` | 该公告命中的组件修复建议数组；每个组件固定四项，键序为 `name`、`affected_resources`、`advisory_count`、`recommended_version` |

组件条目各字段口径：

| 字段 | 说明 |
| --- | --- |
| `name` | 命中告警记录的组件名，逐字回显 |
| `affected_resources` | 贡献了该组件命中告警的资源标识数组；按资源登记顺序去重，每个资源只出现一次 |
| `advisory_count` | 该公告下该组件的告警记录总数，不去重也不合并，按命中告警逐条累加 |
| `recommended_version` | 命中告警里修复版本非空者的最大值，比较口径与组件修复建议视图（`component-fixes`）一致：点分十进制逐段数值比较，含非数字段的候选直接忽略；没有任何可用候选时为 `null` |

`fixes` 按资源登记顺序展开，同一资源内按告警提交顺序聚合组件；同一组件在同一公告下只出现一次，没有任何命中告警的组件不输出。同样支持 `severity` 查询参数（四档严重度，比较忽略大小写），筛选后只保留命中级别的告警再聚合，计数与资源列表随之收缩，排序口径不变；同一筛选条件下各组件告警条数合计与公告汇总、明细视图命中的告警条数完全一致。公告编号不存在或筛选没有命中任何告警时都返回 HTTP 200，`fixes` 为空数组，编号原样回显，仍属成功响应。该入口即时计算且只读，不落记录，告警更新、删除或改严重度与修复版本后立即按新内容重算。

该入口的错误口径与公告明细一致：公告编号为空、缺失或含路径分隔符，携带未知或重复查询参数，`severity` 为空或非法，或声明了非空请求体，都返回 HTTP 400（错误码 `invalid_request`），且不读取业务数据、不改变任何既有状态；`GET` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow` 头只给出 `GET`）。

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

可以为已登记的资源登记一份准入策略，并据此对该资源执行一次只读的准入评估。策略与评估结果都只保存在当前进程内存中（评估结果不落任何记录），服务停止或重启后随资源一起清空，不会写入任何文件；准入评估只检查签名记录是否已登记，不执行验签，也不改变任何晋级条件。每个资源至多保留一份策略。

### 登记策略：`POST /resources/{id}/policies`

请求体必须是一个完整的 JSON 对象，且只允许以下四个字段：

| 字段 | 类型 | 是否必填 | 说明 |
| --- | --- | --- | --- |
| `name` | string | 是 | 非空策略名称，最多 256 个 Unicode 码点，原样回显 |
| `evidence_requirements` | array | 是 | 证据要求，元素只允许 `sbom`、`license`、`provenance`、`signature`，区分大小写；可以为空数组，空表示不检查任何证据，且不得重复 |
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

对资源执行一次只读判定，**不接受请求体**（声明非空 `Content-Length` 即返回 400），也不接受查询参数。服务按该资源的策略读取其生命周期状态、SBOM、许可证声明、构建证明、内容签名记录与全部安全告警，但不写入或修改任何状态。

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
2. **证据**：策略要求但资源尚未登记的证据逐项拒绝，原因代码分别为 `no_sbom`、`no_license`、`no_provenance`、`no_signature`，按此顺序输出；未要求的证据不检查。签名只要求记录已登记，验签结果不参与准入判定。
3. **许可证**：`license_allowlist` 非空，而资源登记的许可证 SPDX 标识不在清单中（或资源未登记许可证）时拒绝，原因代码为 `license_denied`；清单为空时不检查许可证。
4. **严重度**：资源存在严重度**高于**上限（等于上限不算超限）的安全告警时拒绝，原因代码为 `severity_exceeded`，比较忽略大小写。

未命中状态阻断时，证据、许可证、严重度三组条件都会被评估；命中多条时组内与组间均按上面的顺序输出，例如：

```json
{"id":"…","allowed":false,"reasons":["no_sbom","no_license","no_provenance","no_signature","license_denied","severity_exceeded"]}
```

### 策略与评估接口的错误

下列情况都返回 HTTP 400（错误码 `invalid_request`），且不写入或修改任何策略或其他状态：

- 请求体缺失、不是合法 UTF-8、无法解码为 JSON，或顶层不是 JSON 对象；
- 缺少四个字段中任一项、字段为空值（空名称、空证据项或许可证项）、出现未知字段；
- `name` 不是字符串或超过 256 个 Unicode 码点；
- `evidence_requirements` 或 `license_allowlist` 不是数组、元素类型错误、证据项不是 `sbom`/`license`/`provenance`/`signature`，或数组内出现重复值；
- `max_severity` 不是四个合法级别之一；
- 路径标识为空或含 `/`、`\\`；策略登记、查询请求携带任意查询参数；
- 准入评估请求携带请求体或任意查询参数。

路径标识格式合法但资源不存在时，三个接口都返回 HTTP 404（错误码 `resource_not_found`）；资源存在但自身尚未登记策略时，策略查询返回 HTTP 404（错误码 `policy_not_found`），准入评估在全局默认策略（见下文）也未登记时同样返回 HTTP 404（错误码 `policy_not_found`）。对 `/resources/{id}/policies` 使用 `GET`、`POST` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET, POST`）；对 `/resources/{id}/admission` 使用 `POST` 之外的方法返回 HTTP 405（`Allow: POST`）。

任何失败都不会写入策略或评估结果，也不会修改资源、依赖、内容、游标、生命周期状态、安全告警、SBOM 文档、许可证声明、构建来源证明或签名记录；策略仅存于当前进程内存，停止或重启即清空，验签不参与准入判定，也不改变晋级条件。

## 全局默认准入策略

除按资源登记策略外，还可以登记一份全局默认准入策略，作用于所有没有自己策略的资源。全局默认策略至多保留一份，字段取值与校验口径和资源自己的策略完全一致，同样只保存在当前进程内存中，停止或重启即清空，不写入任何文件；本次不提供删除，也不支持多份共存。

### 登记全局默认策略：`POST /policies`

请求体字段与 `POST /resources/{id}/policies` 完全相同（`name`、`evidence_requirements`、`license_allowlist`、`max_severity`，均必填，不允许未知字段）。首次登记成功返回 HTTP 201；内容完全一致（四个字段逐项相同，数组内容与顺序也相同）的再次提交返回 HTTP 200 并保持幂等，不生成第二份记录；已登记后提交任何不同内容返回 HTTP 409（错误码 `policy_conflict`），原策略不变。响应体回显策略内容本身，不附带资源标识，键序固定（`name`、`evidence_requirements`、`license_allowlist`、`max_severity`），紧凑 UTF-8 JSON 以单个换行结束：

```bash
curl -s -X POST http://127.0.0.1:8000/policies \
  -H 'Content-Type: application/json' \
  -d '{"name":"default-gate","evidence_requirements":["sbom"],"license_allowlist":["Apache-2.0","MIT"],"max_severity":"high"}'
```

```json
{"name":"default-gate","evidence_requirements":["sbom"],"license_allowlist":["Apache-2.0","MIT"],"max_severity":"high"}
```

### 查询全局默认策略：`GET /policies`

返回当前唯一一份全局默认策略，形状与登记响应相同（不含资源标识），仍是 HTTP 200；尚未登记时返回 HTTP 404（错误码 `policy_not_found`）。

### 默认策略的生效口径

- 资源自己登记了策略时一切照旧：准入评估（`POST /resources/{id}/admission`）与准入预览（`GET /resources/{id}/admission-preview`）只按资源策略判定。
- 资源没有策略但全局默认策略存在时，这两个入口改按全局默认策略判定；状态、证据、许可证、严重度四组规则与原因代码顺序完全不变，不新增原因代码。准入预览里豁免跳过与 `exempted_count` 的口径不变，仍只统计本资源被豁免的告警。
- 两者都缺失时，两个入口仍返回 HTTP 404（错误码 `policy_not_found`），与既有结果一致。
- 风险评分（`GET /resources/{id}/risk`）在资源没有自己的策略时按全局默认策略的许可证清单判断加分，有自己的策略时仍只看自己的清单。

### 全局默认策略接口的错误

下列情况都返回 HTTP 400（错误码 `invalid_request`），且不写入或修改任何策略或其他状态：

- 登记体缺失、不是合法 UTF-8、无法解码为 JSON，或顶层不是 JSON 对象；
- 缺少四个字段中任一项、字段为空值、出现未知字段；
- 证据项或许可证项重复、证据项越界、名称超长等取值非法（口径与资源策略一致）；
- `GET` 携带请求体；两个入口携带任意查询参数。

对 `/policies` 使用 `GET`、`POST` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET, POST`）。任何失败都不改动全局策略、资源策略、准入结论与既有状态。

## 安全告警豁免（漏洞例外）与准入预览

可以对已登记资源的安全告警逐条登记豁免（例外），表示该公告在该组件上的告警已被接受。豁免只保存在当前进程内存中，服务停止或重启后随资源一起清空，不会写入任何文件。豁免只影响下文的准入预览口径，不改变安全告警本身，也不改变既有准入评估、风险评分或其他任何入口。

### 登记豁免：`POST /resources/{id}/vulnerability-exceptions`

请求体必须是一个完整的 JSON 对象，且只允许以下三个字段，三者均为必填的非空字符串：

| 字段 | 类型 | 是否必填 | 说明 |
| --- | --- | --- | --- |
| `advisory` | string | 是 | 公告编号，非空，与告警逐字匹配，原样回显 |
| `component` | string | 是 | 受影响组件，非空，与告警逐字匹配，原样回显 |
| `reason` | string | 是 | 豁免理由，非空字符串，原样回显（不设长度上限） |

登记时按公告编号与组件名称在该资源的告警中**逐字匹配一条**：两者都做完整字符串比较，**区分大小写**，不做模糊匹配或空白修剪；告警的严重度、摘要与修复版本不参与匹配。不允许额外未知字段。成功返回 HTTP 201，响应体为紧凑 UTF-8 JSON，键序固定（`id`、`advisory`、`component`、`reason`）并以换行结束，其中 `id` 是服务生成的豁免标识：

```bash
curl -s -X POST http://127.0.0.1:8000/resources/$ID/vulnerability-exceptions \
  -H 'Content-Type: application/json' \
  -d '{"advisory":"CVE-2026-0001","component":"openssl","reason":"已评估并接受风险"}'
```

```json
{"id":"…","advisory":"CVE-2026-0001","component":"openssl","reason":"已评估并接受风险"}
```

冲突与失败：

- 同一资源下公告编号与组件均相同的豁免重复提交，返回 HTTP 409（错误码 `duplicate_exception`），原豁免保持不变；公告编号或组件任一不同即视为不同豁免。
- 在该资源的告警中逐字匹配不到任何一条时（含大小写不一致、公告或组件不存在、该资源没有任何告警），返回 HTTP 404（错误码 `vulnerability_not_found`），**不留下任何豁免记录**。
- 匹配按资源隔离：其他资源上的相同告警不构成本资源的匹配依据。

### 查询豁免：`GET /resources/{id}/vulnerability-exceptions`

按登记顺序返回该资源的全部豁免，空集合也是成功响应：

```json
{"exceptions":[{"id":"…","advisory":"CVE-2026-0001","component":"openssl","reason":"已评估并接受风险"}]}
```

每条记录固定四个字段，顺序为 `id`、`advisory`、`component`、`reason`；没有任何豁免时返回 `{"exceptions":[]}`，仍是 HTTP 200。

### 删除单条豁免：`DELETE /resources/{id}/vulnerability-exceptions/{exception-id}`

按豁免标识移除该资源下的单条豁免。请求不接受请求体，也不接受查询参数。成功返回 HTTP 200，并回显被删记录的完整内容（字段与登记响应相同、键序一致并以换行结束）。

豁免标识未知、属于其他资源，或此前已被删除时，返回 HTTP 404（错误码 `exception_not_found`），不改变任何其他豁免。删除后，相同公告编号与组件的豁免可在仍匹配到告警的前提下重新登记。

### 准入预览：`GET /resources/{id}/admission-preview`

只读查询，**只接受 GET**，不接受请求体或查询参数。其判定规则与上文的 `POST /resources/{id}/admission` **完全一致**（同样的状态、证据、许可证、严重度规则与原因顺序），唯一区别是：统计超限严重度时**跳过已被豁免的告警**，其他入口口径一律不变。

成功返回 HTTP 200，响应体为紧凑 UTF-8 JSON，顶层依次为 `id`、`allowed`、`reasons`、`exempted_count` 四个字段并以单个换行结束：

```bash
curl -s "http://127.0.0.1:8000/resources/$ID/admission-preview"
```

```json
{"id":"…","allowed":true,"reasons":[],"exempted_count":1}
```

| 字段 | 说明 |
| --- | --- |
| `id` | 被预览资源的标识 |
| `allowed` | 与准入评估相同口径下的结论，全部条件通过为 `true` |
| `reasons` | 命中的稳定原因代码数组，顺序与准入评估一致；全部通过为空数组 |
| `exempted_count` | 本次判定中因被豁免而跳过的告警条数（按公告编号与组件逐字匹配豁免的告警计数） |

说明：

- 豁免只把对应告警移出超限严重度统计；即使该告警未超上限（本就不会触发 `severity_exceeded`），它被豁免时仍计入 `exempted_count`。
- 状态阻断（`state_blocked`）仍按原规则短路其他检查，但被豁免跳过的告警条数照常计入 `exempted_count`。
- 证据、许可证与状态原因与准入评估完全一致；预览即时计算、不落任何记录，重复调用结果一致。
- 该预览不改变既有 `POST /admission` 的行为：后者仍统计全部告警，也不返回 `exempted_count`。

### 豁免与预览接口的错误

下列情况都返回 HTTP 400（错误码 `invalid_request`），且不写入、不删除任何豁免或其他状态：

- 请求体缺失、不是合法 UTF-8、无法解码为 JSON，或顶层不是 JSON 对象；
- 缺少 `advisory`、`component`、`reason` 中任一项，或出现未知字段；
- 任一字段不是字符串或为空；
- 路径资源标识、豁免标识为空或含 `/`、`\\`；
- 登记、查询与删除请求携带任意查询参数；预览请求携带请求体或任意查询参数。

路径资源标识格式合法但资源不存在时，各入口都返回 HTTP 404（错误码 `resource_not_found`）；资源存在但自身缺少策略、且全局默认策略也未登记时，准入预览返回 HTTP 404（错误码 `policy_not_found`）。方法不符返回 HTTP 405（错误码 `method_not_allowed`，附带 `Allow` 头）：豁免集合为 `Allow: GET, POST`，单条豁免为 `Allow: DELETE`，准入预览为 `Allow: GET`。

任何重复冲突、未知标识或其他失败都不会覆盖或修改已存记录，也不会留下半条豁免；豁免与预览结果仅存于当前进程内存（预览不落记录），失败不改既有状态，既有准入评估行为保持不变。

## 风险评分

可以对已登记的资源即时计算一次风险评分。评分只读取该资源当前的安全告警、SBOM、许可证声明、构建来源证明、内容签名记录、生命周期状态与准入策略，**不写入或修改任何状态**，也不留下任何评分记录；重启后随全部输入一起清空，不写入任何文件。

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
- SBOM 文档、许可证声明、构建来源证明、内容签名记录每缺一份加 5 分；签名只看记录是否已登记，验签不通过不再加减分；
- 资源处于 `withdrawn` 或 `quarantined` 状态时再加 20 分；
- 资源策略的 `license_allowlist` 非空，而资源未登记许可证或登记的 SPDX 标识不在清单内时加 10 分；清单为空时不加；资源没有自己的策略时按全局默认策略的清单判断，两者都没有时不加；
- 总分封顶到 100。

### 风险评分接口的错误

- 路径标识为空或含 `/`、`\\`，或携带任意查询参数，返回 HTTP 400（错误码 `invalid_request`），不执行任何计算。
- 标识格式合法但资源不存在，返回 HTTP 404（错误码 `resource_not_found`），状态不变。
- `GET` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET`）。

## 组件级漏洞关联视图

可以对已登记 SBOM 的资源即时计算一份组件级漏洞关联视图。服务把已登记 SBOM 的组件与该资源的安全告警按组件名称关联起来：告警里的组件与 SBOM 组件名称做完整字符串比较，区分大小写；不做模糊匹配，也不做空白修剪，名称逐字相同才算命中；不比较版本或摘要。该视图**即时计算且只读**，不写入任何状态，也不改变告警、SBOM 与其他既有记录；不提供筛选或分页。

### 查询组件风险：`GET /resources/{id}/component-risks`

成功返回 HTTP 200，响应体为紧凑 UTF-8 JSON，顶层字段为 `components`，正文以换行结束。每个组件给出 `name`、`version`、`digest` 三个字段，命中的告警放在 `advisories` 数组里，每条只含 `id` 与 `severity`：

```bash
curl -s "http://127.0.0.1:8000/resources/$ID/component-risks"
```

```json
{"components":[{"name":"openssl","version":"3.0.0","digest":"aaa…","advisories":[{"id":"…","severity":"high"}]}]}
```

| 字段 | 说明 |
| --- | --- |
| `name` | SBOM 组件名称，原样输出 |
| `version` | SBOM 组件版本，原样输出 |
| `digest` | SBOM 组件摘要，小写 64 位十六进制 |
| `advisories` | 命中该组件的告警数组；每条只含服务生成的告警标识 `id` 与登记时小写形式的 `severity` |

- 组件按 SBOM 提交顺序排列；未命中任何告警的组件照常输出，`advisories` 为空数组。
- 同一组件命中的告警按该资源告警的登记顺序排列，不去重也不合并。
- SBOM 组件列表为空、没有任何命中或该资源没有任何告警时，返回空集合（`{"components":[]}` 或各组件的 `advisories` 均为空），同样算成功响应。

### 组件风险接口的错误

- 路径标识为空或含 `/`、`\\`，或携带任意查询参数，返回 HTTP 400（错误码 `invalid_request`），且不读取业务数据。
- 标识格式合法但资源不存在，返回 HTTP 404（错误码 `resource_not_found`），状态保持不变。
- 资源存在但从未登记 SBOM，返回 HTTP 404（错误码 `sbom_not_found`），不生成任何记录。
- `GET` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET`）。

## 组件修复建议视图

在组件级漏洞关联视图之外，可以对已登记 SBOM 的资源即时计算一份组件修复建议视图。服务把已登记 SBOM 的组件与该资源的全部安全告警按组件名称逐字关联：名称做完整字符串比较，区分大小写，不做模糊匹配，也不做空白修剪；版本与摘要不参与比较。该视图**即时计算且只读**，不写入任何状态，也不改变告警、SBOM 与其他既有记录；不提供筛选或分页。

### 查询组件修复建议：`GET /resources/{id}/component-fixes`

成功返回 HTTP 200，响应体为紧凑 UTF-8 JSON，顶层字段为 `fixes`，正文以单个换行结束。每个组件按 SBOM 提交顺序输出四项：

| 字段 | 说明 |
| --- | --- |
| `name` | SBOM 组件名称，原样输出 |
| `version` | SBOM 组件当前版本，原样输出 |
| `recommended_version` | 命中告警里修复版本（`fixed_version`）非空者的最大值；没有可用候选时为 `null` |
| `advisory_count` | 关联到该组件的告警总数，按登记顺序计数，不去重也不合并 |

```bash
curl -s "http://127.0.0.1:8000/resources/$ID/component-fixes"
```

```json
{"fixes":[{"name":"openssl","version":"3.0.8","recommended_version":"3.0.10","advisory_count":2},{"name":"curl","version":"8.0","recommended_version":null,"advisory_count":0}]}
```

推荐版本的比较规则：

- 版本按点分十进制逐段做**数值比较**（因此 `3.0.10` 大于 `3.0.9`），段数不足的一侧补零后再逐段对齐（`1.2` 与 `1.2.0` 相等）。
- 含非数字段的修复版本（如 `3.0.10-rc`、`v2`、空段）直接忽略，完全不参与最大值比较。
- 命中告警的 `fixed_version` 全部为空（`null`）、全部为不可比较的非数字版本，或组件未命中任何告警时，`recommended_version` 为 `null`。

组件按 SBOM 提交顺序排列；未命中任何告警的组件照常输出，`advisory_count` 为 `0`。SBOM 组件列表为空、没有任何命中或该资源没有任何告警时，返回空集合（`{"fixes":[]}` 或各组件计数为零），同样算成功响应。

### 组件修复建议接口的错误

- 路径标识为空或含 `/`、`\\`，或携带任意查询参数，返回 HTTP 400（错误码 `invalid_request`），且不读取业务数据。
- 标识格式合法但资源不存在，返回 HTTP 404（错误码 `resource_not_found`），状态保持不变。
- 资源存在但从未登记 SBOM，返回 HTTP 404（错误码 `sbom_not_found`），不生成任何记录。
- `GET` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET`）。

该查询即时计算且只读，不写入状态，也不改变告警与 SBOM 记录。

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

镜像代理的缓存入口挂在全局 `/cache` 路径下，不依附任何资源。缓存条目与命中、未命中计数只保存在当前进程内存中，重启即清空，不写入任何文件。

### 写入层：`POST /cache/layers/{digest}`

按摘要接收原始字节流。`{digest}` 必须是 64 位十六进制摘要（大小写均可，统一按小写存储）。请求必须声明 `Content-Type: application/octet-stream` 和合法的 `Content-Length`，服务按声明长度读取字节并用 SHA-256 校验与路径摘要一致、且配额允许时才缓存该层。

```bash
curl -s -X POST http://127.0.0.1:8000/cache/layers/012d8243…  \
  -H 'Content-Type: application/octet-stream' --data-binary @layer.bin
```

成功时返回 HTTP 201（重复提交相同字节返回 HTTP 200 且一切不变），响应体是紧凑 UTF-8 JSON 并以换行结束，回显层摘要、字节数和当前条目数：

```json
{"digest":"012d8243…","size":11,"entries":1}
```

### 读取层：`GET /cache/layers/{digest}`

命中时返回 HTTP 200，响应体是原始缓存字节，`Content-Type: application/octet-stream`，`Content-Length` 为准确长度，并累计一次命中。摘要未缓存时返回 HTTP 404（错误码 `cache_miss`）并累计一次未命中。

### 状态查询：`GET /cache/status`

只读报告条目数、已用字节、配额和命中、未命中计数，不改变任何状态：

```json
{"entries":1,"used_bytes":11,"quota":1048576,"hits":1,"misses":0}
```

### 删除单层：`DELETE /cache/layers/{digest}`

删除挂载在缓存层路径下的单个条目。`{digest}` 同样必须是 64 位十六进制摘要（大小写均可，统一按小写处理）。请求不接受请求体，也不接受查询参数。

成功时返回 HTTP 200，响应体是一行紧凑 UTF-8 JSON 并以换行结束，依次给出 `digest`、`size`、`entries` 三个键（均按此顺序出现）：

```bash
curl -s -X DELETE http://127.0.0.1:8000/cache/layers/012d8243…
```

```json
{"digest":"012d8243…","size":11,"entries":0}
```

| 字段 | 说明 |
| --- | --- |
| `digest` | 被删层的 64 位小写十六进制摘要 |
| `size` | 本次移除的字节数 |
| `entries` | 删除后缓存中剩余的条目数 |

删除后该层字节不再占用配额：已用字节同步回落，随后的新层写入按回落后的用量判断配额。命中与未命中计数保持不变。删除不存在或此前已删除的摘要都返回 HTTP 404（错误码 `cache_miss`）；删除某层后再通过镜像源拉取同一摘要，仍按既有链路回源取回、校验并重新写入缓存。

### 清空缓存：`DELETE /cache`

清空挂载在缓存根路径下的全部条目。请求不接受请求体，也不接受查询参数。

成功时返回 HTTP 200，响应体是一行紧凑 UTF-8 JSON 并以换行结束，依次给出 `removed` 与 `freed_bytes` 两个键：

```bash
curl -s -X DELETE http://127.0.0.1:8000/cache
```

```json
{"removed":2,"freed_bytes":42}
```

| 字段 | 说明 |
| --- | --- |
| `removed` | 本次清掉的缓存条目数 |
| `freed_bytes` | 本次释放的字节数 |

在空缓存上执行清空同样返回 HTTP 200，两个计数都为 `0`；重复清空不报错。清空后已用字节回落为 `0`，后续写入按空缓存判断配额；命中与未命中计数以及配额设置保持不变。

### 缓存接口的错误

下列情况都返回 HTTP 400（错误码 `invalid_request`），且不改变缓存内容与计数：

- 路径摘要不是 64 位十六进制、为空或含分隔符（此时不读取请求体）；
- 写入请求的 `Content-Type` 不是 `application/octet-stream`；
- 写入请求的 `Content-Length` 缺失、取值非法或实际字节不足；
- 任意缓存接口携带查询参数；
- 两个删除入口携带请求体（声明非空或非法的 `Content-Length` 同样拒绝）。

内容字节与路径摘要不一致时返回 HTTP 409（错误码 `digest_mismatch`），不写入任何缓存条目；同一摘要已缓存不同字节时返回 HTTP 409（错误码 `cache_conflict`），保留原条目；写入会使已用字节超过配额时返回 HTTP 409（错误码 `cache_quota_exceeded`），缓存保持原样。删除不存在或已删除的摘要返回 HTTP 404（错误码 `cache_miss`），沿用既有错误 JSON 形状。

对 `/cache/layers/{digest}` 使用 `GET`、`POST`、`DELETE` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: DELETE, GET, POST`）；对 `/cache/status` 使用 `GET` 之外的方法返回 HTTP 405（`Allow: GET`）；对缓存根路径 `/cache` 使用 `DELETE` 之外的方法返回 HTTP 405（`Allow: DELETE`）。跨层批量操作不在本接口范围内。

## 镜像源登记与按摘要拉取

可以登记若干镜像源，并通过某个镜像源按摘要拉取镜像层，或对其登记上游发起探活。镜像源记录只保存在当前进程内存中，重启即清空，不写入任何文件；拉取复用全局 `/cache` 层缓存：命中既有缓存时直接返回原始字节，未命中时向登记的上游地址取回、校验摘要后写入缓存再返回。镜像源之间相互独立，名称全局唯一。

### 登记镜像源：`POST /mirrors`

请求体必须是一个完整的 JSON 对象，且只允许以下两个字段：

| 字段 | 类型 | 是否必填 | 说明 |
| --- | --- | --- | --- |
| `name` | string | 是 | 镜像源名称，非空，全局唯一，原样回显 |
| `upstream` | string | 是 | 上游地址，必须是 `http` 或 `https` 的绝对地址，原样回显 |

成功返回 HTTP 201，响应体为紧凑 UTF-8 JSON，键序固定（`id`、`name`、`upstream`）并以换行结束，其中 `id` 是服务生成的镜像源标识：

```bash
curl -s -X POST http://127.0.0.1:8000/mirrors \
  -H 'Content-Type: application/json' \
  -d '{"name":"primary","upstream":"https://registry.example.invalid/"}'
```

```json
{"id":"…","name":"primary","upstream":"https://registry.example.invalid/"}
```

名称重复登记返回 HTTP 409（错误码 `duplicate_mirror`），原镜像源不被覆盖或合并；名称比较区分大小写且全局唯一。

### 列出镜像源：`GET /mirrors`

按登记顺序返回当前进程中的全部镜像源，空集合也是合法响应：

```json
{"mirrors":[]}
```

每条记录都只含 `id`、`name`、`upstream` 三个字段。

### 查询单个镜像源：`GET /mirrors/{id}`

按标识取得单条镜像源，回显字段与登记响应相同，仍是 HTTP 200。标识合法但镜像源不存在时返回 HTTP 404（错误码 `mirror_not_found`），不改变任何状态。

### 删除镜像源：`DELETE /mirrors/{id}`

删除指定镜像源。成功返回 HTTP 200，响应体回显被删记录的 `id`、`name`、`upstream` 三个字段，键序与登记响应一致，仍是紧凑 UTF-8 JSON 并以单个换行结束。删除会连带清掉该源名下的签名策略，但回显仍只含镜像源三项；删除不影响缓存条目、命中与未命中计数，也不影响跨仓库引用、资源依赖与成品内容。同名镜像源删除后允许重新登记。标识合法但镜像源不存在或已删除时返回 HTTP 404（错误码 `mirror_not_found`），对同一镜像源重复删除同样返回 404，不产生任何新的副作用。

### 按摘要拉取层：`POST /mirrors/{id}/pull/{digest}`

`{digest}` 必须是 64 位十六进制摘要（大小写均可，统一按小写规范化比较）。处理顺序如下：

1. 摘要在 `/cache` 中已存在时，直接返回该层的原始缓存字节，不联系上游，也不改变缓存计数。
2. 缓存未命中时，向登记的上游地址去掉末尾斜杠后拼接 `/layers/<摘要>` 发起 GET，取回该层字节。
3. 对取回的字节计算 SHA-256，只有与路径摘要（小写）逐字一致时才写入缓存。
4. 写入使已用字节超过缓存配额时拒绝写入（见下）。

成功一律返回 HTTP 200，响应体是层的原始字节（无 JSON 包装、无末尾换行），`Content-Type: application/octet-stream`，`Content-Length` 为准确字节数；除首次未命中写入新条目外，拉取不改变缓存的命中、未命中计数。

```bash
curl -s -X POST "http://127.0.0.1:8000/mirrors/$MIRROR_ID/pull/$DIGEST" --output layer.bin
```

拉取相关错误（均不改变缓存）：

- 上游不可达（连接失败、超时等）或返回非 200 状态，返回 HTTP 502（错误码 `mirror_fetch_failed`）。
- 上游返回的字节经 SHA-256 校验与请求摘要不符，返回 HTTP 502（错误码 `mirror_digest_mismatch`），不写入缓存。
- 校验通过但写入会使已用字节超过配额，返回 HTTP 409（错误码 `cache_quota_exceeded`），缓存保持原样，响应体不是层字节。

### 按镜像源批量预取：`POST /mirrors/{id}/prefetch`

在单个摘要拉取之外，可对某个镜像源一次提交多个摘要批量预取。请求体必须是一个完整的 JSON 对象，且只允许 `digests` 一个字段：它必须是非空字符串数组，每个元素都是 64 位十六进制摘要（大小写均可，统一按小写规范化）且数组内不得重复；数组顺序就是逐项处理顺序。

```bash
curl -s -X POST "http://127.0.0.1:8000/mirrors/$MIRROR_ID/prefetch" \
  -H 'Content-Type: application/json' \
  -d '{"digests":["'"$DIGEST_A"'","'"$DIGEST_B"'"]}'
```

逐项复用既有单摘要拉取链路：摘要已在缓存中命中即直接返回（不联系上游、不改缓存计数），未命中则回源取回、校验摘要后写入缓存。无论各项成败，整体成功一律返回 HTTP 200，响应体是紧凑 UTF-8 JSON 一行并以单个换行结束。顶层键序固定为 `id`、`results`，`results` 按提交顺序展开，每项依次为 `digest`、`status`、`size`：

- `status` 取 `cached`（缓存命中）、`fetched`（本次新取回并写入缓存）或 `failed`（该项失败）。
- 失败项在三项之外再带 `error` 字段，值沿用既有拉取与签名判定的稳定错误码（`mirror_fetch_failed`、`mirror_digest_mismatch`、`cache_quota_exceeded`、`signature_missing`、`key_not_trusted`、`digest_uncovered`、`signature_invalid`），失败项的 `size` 为 `0`。

```json
{"id":"…","results":[{"digest":"…","status":"cached","size":17},{"digest":"…","status":"fetched","size":22},{"digest":"…","status":"failed","size":0,"error":"mirror_fetch_failed"}]}
```

单项失败不影响其余项继续处理，全部失败时同样返回 HTTP 200 并逐项报告。配额不足、摘要不符或签名失败只影响该项，不回滚其他项已写入的缓存。镜像源已登记签名策略时，每个摘要都用同一组签名请求头（`X-Key-Id`、`X-Signature`、`X-Signed-Digest`）复用与单摘要拉取同一处签名判定（见下文「拉取时的签名校验」）逐项校验，覆盖检查（`cover_digest` 为 `true` 时）对照各自被拉摘要；签名判定按缺头、密钥、覆盖、签名的固定顺序逐项执行，命中即止、只报一个错误码——多项同时命中时只报排在最前的 `key_not_trusted`，不再出现其他错误码；与单摘要拉取的唯一分工是：预取签名头取值非法不产生 `invalid_request`，而是归入四个签名判定错误码之一（详见下文）。未登记策略时签名头被忽略。缓存条目的命中与未命中计数仍按既有拉取规则变化（预取的命中判定使用不计计数的读取，与单摘要拉取一致），本接口不改计数口径。

预取结果与写入的缓存条目只存进程内存，重启清空，不生成文件。

### 镜像源上游探活：`POST/GET /mirrors/{id}/probe`

在拉取之外，可以对某个已登记镜像源发起一次对其登记上游地址的真实探活，并读取最近一次探活结果。探活对登记的上游地址发起一次 GET 连接尝试：能完成连接并收到上游的 HTTP 响应（无论状态码是否为 2xx）即为可达；连接失败、超时等无法完成尝试的情况为不可达。探活结果只存进程内存，每个镜像源只保留最近一次结果，新探活覆盖旧结果，重启清空，不写入任何文件，也不改变缓存条目、命中与未命中计数或其他任何既有状态。

`POST /mirrors/{id}/probe` 触发一次真实探活并覆盖该镜像源上一次的探活结果。请求不接受请求体，也不接受查询参数。可达与不可达都是 HTTP 200 的正常业务结果，不视为服务错误。成功时返回紧凑 UTF-8 JSON 一行，响应正文以单个换行结束，键序固定为 `id`、`reachable`、`status_code`、`latency_ms`：

- 可达时 `reachable` 为 `true`，`status_code` 是上游响应的状态码，`latency_ms` 是本次尝试的非负整数耗时毫秒：

```bash
curl -s -X POST "http://127.0.0.1:8000/mirrors/$MIRROR_ID/probe"
```

```json
{"id":"…","reachable":true,"status_code":200,"latency_ms":7}
```

- 不可达时 `reachable` 为 `false`，`status_code` 与 `latency_ms` 均为 `null`，并在四项之外多出一个 `error` 字段，值是稳定错误码 `probe_failed`：

```json
{"id":"…","reachable":false,"status_code":null,"latency_ms":null,"error":"probe_failed"}
```

`GET /mirrors/{id}/probe` 只读取最近一次探活结果，成功形状与 POST 完全相同；GET 不触发探活、不写任何状态。镜像源从未探活时 GET 返回 HTTP 404（错误码 `probe_not_found`）。

探活相关错误：

- 路径标识为空或含 `/`、`\\`，或 GET、POST 携带任意查询参数，POST 携带请求体（声明非空或非法的 `Content-Length` 同样拒绝），返回 HTTP 400（错误码 `invalid_request`），不发起探活、不写入结果。
- 标识合法但镜像源不存在时，GET 与 POST 都返回 HTTP 404（错误码 `mirror_not_found`），不改变状态。
- 探活入口只允许 GET 与 POST，其他方法一律返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET, POST`）。

### 登记镜像源签名策略：`POST /mirrors/{id}/signature-policy`

每个镜像源最多登记一份签名策略，登记后该镜像源的拉取必须携带签名请求头。请求体必须是一个完整的 JSON 对象，且只允许以下三个字段：

| 字段 | 类型 | 是否必填 | 说明 |
| --- | --- | --- | --- |
| `algorithm` | string | 是 | 签名算法，只允许 `hmac-sha256`、`hmac-sha512`，区分大小写 |
| `keys` | array | 是 | 受信密钥标识数组，非空，元素为非空字符串且不得重复，原样回显 |
| `cover_digest` | boolean | 是 | 为 `true` 时被签摘要必须覆盖被拉层的摘要 |

首次登记返回 HTTP 201，响应体回显镜像源 `id` 与上述三项内容（键序固定为 `id`、`algorithm`、`keys`、`cover_digest`，紧凑 JSON 以换行结束）；内容完全相同的重复提交返回 HTTP 200，内容不同返回 HTTP 409（错误码 `mirror_policy_conflict`），原策略不被覆盖。

```bash
curl -s -X POST "http://127.0.0.1:8000/mirrors/$MIRROR_ID/signature-policy" \
  -H 'Content-Type: application/json' \
  -d '{"algorithm":"hmac-sha256","keys":["key-one"],"cover_digest":true}'
```

```json
{"id":"…","algorithm":"hmac-sha256","keys":["key-one"],"cover_digest":true}
```

### 查询镜像源签名策略：`GET /mirrors/{id}/signature-policy`

返回该镜像源的签名策略，形状与登记响应相同，仍是 HTTP 200。镜像源存在但从未登记策略时返回 HTTP 404（错误码 `mirror_policy_not_found`）。

### 删除镜像源签名策略：`DELETE /mirrors/{id}/signature-policy`

只删除镜像源的签名策略，镜像源本身仍然保留。成功返回 HTTP 200，响应体回显被删策略的全部字段，键序固定为 `id`、`algorithm`、`keys`、`cover_digest`，紧凑 JSON 以换行结束。删除后该镜像源的按摘要拉取立即回到没有签名策略的既有行为。镜像源存在但未登记策略、或策略已被删除时返回 HTTP 404（错误码 `mirror_policy_not_found`），重复删除同样返回 404，不产生任何新的副作用。

### 拉取时的签名校验

单摘要拉取与批量预取共用同一处签名判定：镜像源登记了签名策略后，请求必须携带三个签名头 `X-Key-Id`（密钥标识）、`X-Signature`（十六进制签名值）与 `X-Signed-Digest`（被签的 64 位十六进制摘要）。校验在层内容就绪（缓存命中或回源并校验摘要通过）之后、写缓存与返回字节之前进行，按既有口径重算：以密钥标识的 UTF-8 字节为密钥，对小写被签摘要文本做策略算法的 HMAC。两条链路都按以下固定顺序判定，命中即止，只报一个错误码：

1. 缺少任一签名请求头，返回 HTTP 403（错误码 `signature_missing`）。
2. `X-Key-Id` 不在策略的 `keys` 中，返回 HTTP 403（错误码 `key_not_trusted`）。
3. 策略 `cover_digest` 为 `true` 且 `X-Signed-Digest` 与被拉层摘要不符，返回 HTTP 403（错误码 `digest_uncovered`）。
4. 重算签名与 `X-Signature` 不一致（比对忽略大小写），返回 HTTP 403（错误码 `signature_invalid`）。

两条链路的唯一分工是对取值非法的签名请求头的处理：

- **单摘要拉取（`POST /mirrors/{id}/pull/{digest}`）**：在进入上述四档判定之前先校验签名头取值——`X-Key-Id`、`X-Signature` 必须是非空字符串，`X-Signed-Digest` 必须是 64 位十六进制串；任一取值非法一律按请求错误拒绝，返回 HTTP 400（错误码 `invalid_request`），不进行后面的四档判定。这条“取值非法即 400”的口径只作用于单摘要拉取链路。
- **批量预取（`POST /mirrors/{id}/prefetch`）**：逐项校验不返回 400，只产生上面四个签名判定错误码（体现在失败项的 `error` 上）：空或不受信的密钥标识一律按 `key_not_trusted` 处理（且密钥信任排在任何取值比较之前）；`X-Signed-Digest` 不是合法十六进制时不可能覆盖被拉摘要，按 `digest_uncovered` 处理；其他取值不可能与重算签名相等，按 `signature_invalid` 处理。同一项多个条件同时命中时只报固定顺序中最靠前的一个。

校验不通过时不返回层字节、不写缓存、不改缓存计数；校验通过时仍返回原始层字节。未登记策略的镜像源拉取与预取行为与既有完全一致，即使携带签名请求头也不改变结果。

### 镜像源接口的错误

下列情况都返回 HTTP 400（错误码 `invalid_request`），且不写入任何镜像源、不改变缓存或其他状态：

- 路径标识为空或含路径分隔符（`/`、`\\`），或拉取路径中的摘要不是 64 位十六进制；
- 登记请求体缺失、不是合法 UTF-8 JSON，或顶层不是 JSON 对象；
- 缺少 `name`、`upstream`，出现未知字段，任一字段不是字符串或为空；
- `upstream` 不是 `http` 或 `https` 的绝对地址；
- 签名策略缺少 `algorithm`、`keys`、`cover_digest` 中任一字段，出现未知字段，`algorithm` 不是两个允许值之一，`keys` 不是非空数组、元素不是非空字符串或出现重复，`cover_digest` 不是布尔值；
- 仅在单摘要拉取链路（`POST /mirrors/{id}/pull/{digest}`）：已登记策略的拉取请求中签名请求头取值非法（`X-Key-Id`、`X-Signature` 为空，或 `X-Signed-Digest` 不是 64 位十六进制）时按请求错误返回 400；该 400 口径不作用于批量预取（预取逐项归入签名判定错误码，见「拉取时的签名校验」）；
- 批量预取请求体缺失、不是合法 UTF-8 JSON、顶层不是 JSON 对象，或 `digests` 缺失、不是数组、为空，元素不是字符串或不是 64 位十六进制、数组内重复，或出现 `digests` 之外的未知字段；
- 两个删除入口携带请求体；
- 任意镜像源接口携带查询参数（批量预取携带任意查询参数时同样返回 400，且不写入任何缓存条目）。

路径标识格式合法但镜像源不存在时，单条查询、删除、拉取、批量预取、探活与签名策略接口都返回 HTTP 404（错误码 `mirror_not_found`），且不改变状态；探活 GET 对从未探活的镜像源另返回 HTTP 404（错误码 `probe_not_found`）。方法不符返回 HTTP 405（错误码 `method_not_allowed`，响应带 `Allow` 头）：`/mirrors` 为 `Allow: GET, POST`，`/mirrors/{id}` 为 `Allow: DELETE, GET`，`/mirrors/{id}/pull/{digest}` 为 `Allow: POST`，`/mirrors/{id}/prefetch` 为 `Allow: POST`，`/mirrors/{id}/probe` 为 `Allow: GET, POST`，`/mirrors/{id}/signature-policy` 为 `Allow: DELETE, GET, POST`。

镜像源数据、签名策略、最近一次探活结果与由拉取写入的缓存条目均仅存于当前进程内存，停止或重启即清空，不生成任何文件；探活不改变缓存条目与计数；缓存条目的删除与清空通过上文 `/cache` 的两个删除入口完成，镜像源的并发处理不在当前范围内。

## 跨仓库引用与解析

可以把一个已登记的本地资源（起点）指向其他仓库中的资源。登记跨仓库引用时，服务会即时向上游仓库取回远端资源的元数据、校验摘要，并在本地**生成或复用**一条资源记录，同时建立一条从起点资源指向该资源的依赖边。解析出的边与人工登记的边完全同构，一同参与依赖拓扑与影响分析，排序仍按资源登记顺序。

引用记录同样只保存在当前进程内存中，重启即清空，不写入任何文件；批量与并发不在当前范围内。

### 登记跨仓库引用：`POST /resources/{id}/cross-references`

`{id}` 是起点本地资源的标识，必须已经存在。请求体必须是一个完整的 JSON 对象，且只允许以下四个字段：

| 字段 | 类型 | 是否必填 | 说明 |
| --- | --- | --- | --- |
| `repository` | string | 是 | 远端仓库名称，非空；名称首次出现时与 `upstream` 绑定，之后同名必须同址 |
| `upstream` | string | 是 | 远端仓库地址，必须是 `http` 或 `https` 的绝对地址，原样回显 |
| `remote_id` | string | 是 | 远端资源标识，非空，且不得包含 `/`、`\\` |
| `digest` | string | 是 | 期望的远端资源 64 位十六进制摘要，按小写规范化 |

成功返回 HTTP 201，响应体为紧凑 UTF-8 JSON，以换行结束，先回显起点 `resource_id`，再依次回显登记体的四个键：

```bash
curl -s -X POST http://127.0.0.1:8000/resources/$LOCAL_ID/cross-references \
  -H 'Content-Type: application/json' \
  -d '{"repository":"partner","upstream":"https://repo.example.invalid/","remote_id":"remote-42","digest":"aaaa…aaaa"}'
```

```json
{"resource_id":"<起点 id>","repository":"partner","upstream":"https://repo.example.invalid/","remote_id":"remote-42","digest":"aaaa…aaaa"}
```

处理顺序如下，任何一步失败都不会留下引用、不会建边、不会生成本地资源，也不改变其他既有状态：

1. **请求与绑定校验（本地）**：起点资源必须存在；同一 `repository` 名称已绑定不同 `upstream` 时拒绝；同一 `repository` 与 `remote_id` 的引用已登记过时拒绝。
2. **远端取回**：沿用镜像源拉取的地址拼接规则——去掉 `upstream` 末尾斜杠后拼接 `/resources/<remote_id>`（远端标识按路径段做百分号编码）发起 GET。
3. **元数据与摘要校验**：远端必须返回 200 与 JSON 对象，且含 `name`、`category`、`digest`、`source` 四个字段；类型、类别（四个合法类别之一，大小写无关）与摘要格式必须合法，值不得为空或为 `null`；远端摘要必须与请求体期望摘要（小写）逐字一致。
4. **本地身份与依赖边校验**：同摘要的本地资源仅在名称与类别也一致时复用（`source` 不参与身份判断，保留本地原值）；随后预检依赖边。
5. **缓存写入**：把远端返回的元数据原始字节以（已校验的）资源摘要为键写入全局 `/cache` 层缓存；同摘要同字节幂等，同摘要不同字节冲突，配额不足同样拒绝。
6. **提交**：生成或复用本地资源、建立依赖边、保存引用记录与仓库绑定。

### 查询引用列表：`GET /resources/{id}/cross-references`

按登记顺序返回该起点资源的全部跨仓库引用，空集合也是合法响应：

```json
{"cross_references":[{"resource_id":"<起点 id>","repository":"partner","upstream":"https://repo.example.invalid/","remote_id":"remote-42","digest":"aaaa…aaaa"}]}
```

每条记录都只含 `resource_id` 与登记体的四个键，共五个字段。

### 跨仓库引用接口的错误

请求侧问题返回 HTTP 400（错误码 `invalid_request`），且不联系上游、不改变任何状态：

- 请求体缺失、不是合法 UTF-8 JSON，或顶层不是 JSON 对象；
- 缺少任一字段、出现未知字段、字段不是字符串或为空值（`null`、空串、纯空白）；
- `remote_id` 含路径分隔符（`/`、`\\`）；`digest` 不是 64 位十六进制字符串；
- `upstream` 不是 `http` 或 `https` 的绝对地址；
- 路径资源标识为空或含 `/`、`\\`；携带任意查询参数。

其余错误：

| 场景 | HTTP 状态 | 错误码 |
| --- | --- | --- |
| 起点资源不存在 | 404 | `resource_not_found` |
| 方法不符（`GET`、`POST` 之外），响应带 `Allow: GET, POST` | 405 | `method_not_allowed` |
| 同名仓库已绑定不同上游地址 | 409 | `repository_conflict` |
| 同一仓库与远端标识重复登记 | 409 | `duplicate_reference` |
| 本地已有同摘要资源但名称或类别不一致 | 409 | `identity_conflict` |
| 同向依赖边已存在 | 409 | `duplicate_dependency` |
| 自环或新边会引入环（图保持不变） | 409 | `dependency_cycle` |
| 缓存写入遇同摘要不同字节 | 409 | `cache_conflict` |
| 缓存写入超过配额 | 409 | `cache_quota_exceeded` |
| 上游连接失败、超时或返回非 200 | 502 | `remote_unreachable` |
| 元数据缺字段、类型错误或摘要格式非法 | 502 | `resolution_failed` |
| 远端摘要与期望摘要不符 | 502 | `remote_digest_mismatch` |

`repository_conflict` 与 `duplicate_reference` 在联系上游之前判定；502 类失败不写缓存、不建引用、不建边、不生成本地资源。依赖边的重复与成环语义与 `POST /resources/{id}/dependencies` 一致：已经间接可达但尚不存在的直接边仍正常建立。解析写入缓存的字节也出现在 `/cache` 的条目与用量统计中，可经 `/cache/layers/{digest}` 与 `/cache` 的既有入口读取或删除；除按已校验摘要写入外，缓存与镜像源的其他行为不变。

## 内容签名与验签

可以为已登记的资源登记一条内容签名，并对已登记签名执行只读验签。签名记录只保存在当前进程内存中，服务停止或重启后随资源一起清空，不会写入任何文件；验签即时计算，不留下任何记录。每个资源至多保留一条签名记录。

### 登记签名：`POST /resources/{id}/signatures`

请求体必须是一个完整的 JSON 对象，且只允许以下五个字段：

| 字段 | 类型 | 是否必填 | 说明 |
| --- | --- | --- | --- |
| `signer` | string | 是 | 签名者，非空文本，最多 256 个 Unicode 码点，原样回显 |
| `algorithm` | string | 是 | 只允许 `hmac-sha256` 与 `hmac-sha512`，区分大小写 |
| `key_id` | string | 是 | 密钥标识，非空文本，最多 256 个 Unicode 码点；其字节即验签密钥 |
| `signature` | string | 是 | 对应算法的十六进制签名值，接受大小写混合，统一按小写保存 |
| `digest` | string | 是 | 被签名的 64 位十六进制摘要，接受大小写混合，统一按小写保存 |

签名长度必须与算法匹配：`hmac-sha256` 的签名值为 64 位十六进制，`hmac-sha512` 为 128 位；长度不符即为格式非法，返回 HTTP 400。登记时不校验签名值本身是否正确，也不校验摘要是否与资源登记摘要一致——前者由验签判定，后者只在验签时报告冲突。

首次登记成功返回 HTTP 201，响应体为紧凑 UTF-8 JSON，键序固定（`id`、`signer`、`algorithm`、`key_id`、`signature`、`digest`）并以换行结束：

```bash
SIG=$(printf '%s' "$DIGEST" | openssl dgst -sha256 -hmac "$KEY_ID" | sed 's/^.*= //')
curl -s -X POST http://127.0.0.1:8000/resources/$ID/signatures \
  -H 'Content-Type: application/json' \
  -d "{\"signer\":\"alice\",\"algorithm\":\"hmac-sha256\",\"key_id\":\"$KEY_ID\",\"signature\":\"$SIG\",\"digest\":\"$DIGEST\"}"
```

```json
{"id":"…","signer":"alice","algorithm":"hmac-sha256","key_id":"secret","signature":"…","digest":"…"}
```

幂等与冲突：

- 规范化后的内容完全相同（签名者、算法、密钥标识、小写签名值与小写摘要均一致）再次登记视为幂等，返回 HTTP 200，回显内容与首次登记相同，不生成第二条记录。
- 已有签名记录时提交任何不同内容（任一字段不同）返回 HTTP 409（错误码 `signature_conflict`），原记录保持不变。

### 查询签名：`GET /resources/{id}/signatures`

返回该资源唯一一条签名记录，形状与登记响应相同，仍是 HTTP 200。资源存在但从未登记签名时返回 HTTP 404（错误码 `signature_not_found`）。

### 验签：`POST /resources/{id}/signatures/verify`

只读验签，不接受请求体字段、不读取业务输入，所有输入都取自已登记记录与资源记录：

1. 服务按登记的 `algorithm` 与 `key_id` 重算签名：对登记的小写 `digest` 文本计算 HMAC，密钥取 `key_id` 的 UTF-8 字节序列——`hmac-sha256` 产出 64 位小写十六进制，`hmac-sha512` 产出 128 位。
2. 将重算值与登记的 `signature` 逐字比对：一致时 `valid` 为 `true`，不一致为 `false`；两者都是正常 HTTP 200 响应，不是服务错误。
3. 记录的 `digest` 与资源登记摘要不一致时返回 HTTP 409（错误码 `signed_digest_mismatch`），不给出 `valid`。

成功时响应体为紧凑 UTF-8 JSON，键序固定（`id`、`valid`）并以换行结束：

```bash
curl -s -X POST http://127.0.0.1:8000/resources/$ID/signatures/verify
```

```json
{"id":"…","valid":true}
```

验签不写入或修改任何状态，重复调用结果一致。

### 签名接口的错误

下列情况都返回 HTTP 400（错误码 `invalid_request`），且不写入或修改任何签名或其他状态：

- 请求体缺失、不是合法 UTF-8、无法解码为 JSON，或顶层不是 JSON 对象；
- 缺少 `signer`、`algorithm`、`key_id`、`signature`、`digest` 中任一字段，或出现未知字段、字段为空值；
- `signer`、`key_id` 不是字符串、为空或超过 256 个 Unicode 码点；
- `algorithm` 不是 `hmac-sha256`/`hmac-sha512`（区分大小写）；
- `digest` 不是 64 位十六进制文本；`signature` 不是十六进制文本或长度与算法不符；
- 路径标识为空或含 `/`、`\\`；登记、查询与验签请求携带任意查询参数。

路径标识格式合法但资源不存在时，三个接口都返回 HTTP 404（错误码 `resource_not_found`）；资源存在但尚未登记签名时，查询与验签返回 HTTP 404（错误码 `signature_not_found`）。对 `/resources/{id}/signatures` 使用 `GET`、`POST` 之外的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET, POST`）；对 `/resources/{id}/signatures/verify` 使用 `POST` 之外的方法返回 HTTP 405（`Allow: POST`）。

任何失败都不会写入签名或验签记录，也不会修改资源、依赖、内容、游标、生命周期状态、安全告警、SBOM 文档、许可证声明、构建来源证明、准入策略、通知、镜像源、跨仓库引用或缓存；签名记录仅存于当前进程内存，停止或重启即清空，不生成任何文件。

## 运行测试

```bash
python -m unittest discover -s tests -v
```

## 开发边界

- 新增接口必须在公开文档中说明启动方式、请求和响应行为。
- 持久化数据和生成文件不得提交到 Git。
- 不得把密钥、访问令牌、私有验证脚本或控制系统资料写入仓库。
- 对已有公开接口的更改应保持向后兼容，除非任务明确要求破坏性升级。
- 当前公开业务接口为健康检查、上述资源登记/查询接口、资源依赖关系登记、依赖拓扑查询与影响分析接口、资源内容校验接口、分块上传、组装、分块上传会话状态查询与成品读取接口，资源生命周期状态读取与提交接口，以及按既有晋级检查顺序即时给出 `content_not_complete`、`dependency_blocked` 原因并逐条列出被隔离或撤回的可达依赖、即时计算且只读不落记录的晋级阻塞明细视图（`release-blockers`）接口，安全告警（漏洞）的登记、查询与按告警标识删除单条告警接口（删除立即在单条查询、严重度筛选、准入评估与预览、风险评分、组件漏洞关联、组件修复建议与全局公告汇总中生效；已登记豁免不随删除撤回、暂时失去匹配对象并停止计入豁免条数，同一公告与组件的告警再次登记后既有豁免立即重新生效），把全部资源告警按公告编号汇总、组内资源按登记顺序去重、公告按最早告警提交顺序展开、可按严重度筛选、即时计算且只读不落记录的全局告警汇总视图（`advisories`）接口，以及按公告编号逐字下钻该公告的告警明细、按资源登记顺序与该资源内告警提交顺序展开、可按严重度筛选、即时计算且只读不落记录的公告明细视图（`advisories/{advisory}`）接口，以及按公告编号下钻该公告命中组件的修复建议、按资源登记顺序与告警提交顺序聚合组件、组件只出现一次、资源按登记顺序去重、计数逐条累加、推荐修复版本与 `component-fixes` 同口径取点分十进制最大值、可按严重度筛选、即时计算且只读不落记录的公告组件修复建议视图（`advisories/{advisory}/fixes`）接口，SBOM 文档与许可证声明的登记与查询接口，构建来源证明（provenance）的登记与查询接口，准入策略的登记与查询接口和只读准入评估接口，全局默认准入策略的登记与查询接口（没有自己策略的资源在准入评估、准入预览与风险评分中改按默认策略判定），按资源登记、查询与删除安全告警豁免（漏洞例外）的接口，以及判定与准入评估一致、但超限严重度只统计未豁免告警并返回 `exempted_count` 的只读准入预览接口（`admission-preview`），按资源即时计算的风险评分接口，把已登记 SBOM 的组件与该资源安全告警按组件名称逐字、区分大小写关联、即时计算且只读的组件级漏洞关联视图（`component-risks`）接口，以及同样按名称逐字关联、即时计算且只读、给出当前版本与点分十进制最大非空修复版本建议的组件修复建议视图（`component-fixes`）接口，以及通知记录的登记与查询接口，以及全局镜像层缓存的写入、读取、状态查询、单层删除与清空接口，以及全局镜像源及其签名策略的登记、查询与删除，和通过镜像源按摘要拉取镜像层、对一组层摘要按镜像源批量预取、对镜像源登记上游发起探活（GET 只读最近一次结果、POST 触发一次真实探活并覆盖旧结果）的接口，以及把本地资源指向其他仓库资源、登记时即时解析远端元数据并建立依赖边的跨仓库引用登记与查询接口，以及内容签名的登记、查询与只读验签接口，以及沿依赖闭包把每个资源的告警总数与最高严重度即时汇总、只读不落记录的依赖漏洞传导视图（`dependency-vulnerability-impact`）接口；资源、依赖、分块会话、成品内容、生命周期状态、安全告警、安全告警豁免、SBOM 文档、许可证声明、构建来源证明、准入策略、全局默认准入策略、通知记录、镜像源登记、最近一次探活结果、跨仓库引用、内容签名记录与缓存条目及计数均仅存于进程内存（跨仓库引用解析失败不留引用、不建边、不生成本地资源；缓存的删除与清空只移除条目并回落已用字节，不改动资源、依赖、成品、镜像源、跨仓库引用等既有状态，也不重置命中与未命中计数），准入评估结果、准入预览结果、风险评分、晋级阻塞明细、全局告警汇总、公告组件修复建议与签名验签均即时计算、不落记录、不承诺跨进程或重启后的保存。
- 分块能力明确不承诺以下行为：重启后的断点续传（重启清空全部会话与成品）、并发上传的加锁与顺序保证、以及跨资源的批量上传或批量组装。每个分块请求独立校验，冲突时以 409 拒绝且不覆盖既有字节。

