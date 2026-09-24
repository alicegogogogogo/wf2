# 数字资源供应链与溯源平台

这是一个面向代码、AI 模型、数据集和构建产物的后端服务基线。当前版本提供可运行的 HTTP 服务、健康检查以及进程内的资源登记与查询接口。

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

资源之间可以登记有向依赖关系：`A` 依赖 `B` 表示 `B` 是 `A` 的上游（构建 `A` 需要先有 `B`）。关系只允许连接已登记的资源，与资源本身一样仅保存在当前进程内存中，服务停止后自然清空。关系图始终保持无环：自环或会形成环的关系一律拒绝。

### 登记依赖：`POST /resources/{id}/dependencies`

请求体是只含一个字段的 JSON 对象：

| 字段 | 类型 | 是否必填 | 说明 |
| --- | --- | --- | --- |
| `dependency_id` | string | 是 | 被依赖资源的标识；非空，且不得含 `/`、`\\` |

不允许额外未知字段。成功时返回 HTTP 201，表示该条有向关系的紧凑 JSON：

```bash
curl -s -X POST http://127.0.0.1:8000/resources/$A_ID/dependencies \
  -H 'Content-Type: application/json' \
  -d '{"dependency_id":"<B 的 id>"}'
```

```json
{"resource_id":"<A 的 id>","dependency_id":"<B 的 id>"}
```

冲突与错误：

- 相同起点、相同终点的同向关系重复提交时返回 HTTP 409（错误码 `duplicate_dependency`），不会覆盖或重复记录。
- 自环（`dependency_id` 等于路径中的起点标识）或会使关系图成环的提交返回 HTTP 409（错误码 `dependency_cycle`），关系与资源均保持原状。
- 路径中的起点或 `dependency_id` 指向不存在的资源时返回 HTTP 404（错误码 `resource_not_found`），不建立任何关系。
- 路径标识为空或含 `/`、`\\`，请求体缺失、不是合法 UTF-8 JSON、顶层不是对象、缺少 `dependency_id`、`dependency_id` 不是字符串、为空或含分隔符，以及出现未知字段或查询参数时，返回 HTTP 400（错误码 `invalid_request`）。
- 该路径未声明的方法返回 HTTP 405（错误码 `method_not_allowed`，`Allow: GET, POST`）。

### 查询依赖：`GET /resources/{id}/dependencies`

列出从起点出发沿依赖边可达的全部资源（直接与间接依赖），响应形状为：

```json
{"dependencies":[…]}
```

数组中每项是完整的资源对象，按资源登记顺序排列；每个资源最多出现一次（菱形依赖中的汇合节点只列一次），起点自身永不出现在结果中。起点没有任何依赖时返回空数组，这仍是成功响应：

```json
{"dependencies":[]}
```

### 影响分析：`GET /resources/{id}/impact`

沿依赖边的反方向列出直接或间接依赖起点的全部资源（即起点发生变化时会被波及的下游资源），响应形状为：

```json
{"resources":[…]}
```

结果按资源登记顺序排列，且不包含起点自身；没有任何资源依赖起点时返回 `{"resources":[]}`。

### 拓扑查询的错误

两类查询中，路径标识为空或含 `/`、`\\` 时返回 HTTP 400（错误码 `invalid_request`）；起点资源不存在时返回只读的 HTTP 404（错误码 `resource_not_found`）；携带任何查询参数返回 HTTP 400；对依赖查询路径使用 `GET`、`POST` 之外的方法，或对影响分析路径使用 `GET` 之外的方法，均返回 HTTP 405（错误码 `method_not_allowed`，并附带相应的 `Allow` 头）。以上错误都不改变资源、关系或分页游标。


### 错误响应与方法限制

- 请求体缺失、无法解码或顶层不是 JSON 对象，返回 HTTP 400（错误码 `invalid_request`），不改变状态、不留下半条记录。
- 字段类型错误、必填字段缺失、空名称、非法类别、非法摘要、额外未知字段同样返回 HTTP 400，不做部分接受。
- 资源路径收到未声明的方法时返回 HTTP 405（错误码 `method_not_allowed`，附带 `Allow` 头），仍是 JSON 错误且不改变资源。
- 错误响应体形如：`{"error":"<稳定错误码>","message":"<说明>"}`。

## 运行测试

```bash
python -m unittest discover -s tests -v
```

## 开发边界

- 新增接口必须在公开文档中说明启动方式、请求和响应行为。
- 持久化数据和生成文件不得提交到 Git。
- 不得把密钥、访问令牌、私有验证脚本或控制系统资料写入仓库。
- 对已有公开接口的更改应保持向后兼容，除非任务明确要求破坏性升级。
- 当前公开业务接口为健康检查、资源登记/查询接口以及上述依赖登记/拓扑查询/影响分析接口；资源与依赖关系数据仅存于进程内存，不承诺跨进程或重启后的保存。

