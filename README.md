# 数字资源供应链与溯源平台

这是一个面向代码、AI 模型、数据集和构建产物的后端服务基线。当前版本提供可运行的 HTTP 服务、健康检查、进程内的资源登记与查询、资源之间的依赖关系登记、拓扑查询与影响分析接口，以及按资源标识提交原始字节的内容校验接口。

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

## 运行测试

```bash
python -m unittest discover -s tests -v
```

## 开发边界

- 新增接口必须在公开文档中说明启动方式、请求和响应行为。
- 持久化数据和生成文件不得提交到 Git。
- 不得把密钥、访问令牌、私有验证脚本或控制系统资料写入仓库。
- 对已有公开接口的更改应保持向后兼容，除非任务明确要求破坏性升级。
- 当前公开业务接口为健康检查、上述资源登记/查询接口、资源依赖关系登记、依赖拓扑查询与影响分析接口，以及资源内容校验接口；资源与依赖数据仅存于进程内存，不承诺跨进程或重启后的保存。

