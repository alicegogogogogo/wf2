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

不带查询参数时，按创建顺序返回当前进程中的全部资源，空集合也是合法 JSON：

```json
{"resources":[]}
```

#### 筛选

支持 `category`、`name`、`digest` 三个查询参数，多个条件同时出现时只保留全部匹配的资源：

- `category`：比较时忽略大小写，取值必须是 `code`、`model`、`dataset`、`artifact` 之一；响应中的类别仍按小写形式输出。
- `name`：完整字符串精确比较，不做模糊匹配、大小写折叠或空白修剪。
- `digest`：接受大小写混合的 64 位十六进制值，按登记时的小写规范形式比较。

过滤结果仍按资源创建顺序排列；无命中时返回空列表而非错误：

```json
{"resources":[],"next_cursor":null}
```

#### 分页

用 `limit` 与 `cursor` 控制分页：`limit` 缺省为 50，最大为 100，必须是十进制正整数。首次请求不带 `cursor` 时从首项开始；启用筛选或分页后，响应依次包含 `resources` 与 `next_cursor`：

```json
{"resources":[…],"next_cursor":"…"}
```

还有后续资源时 `next_cursor` 是非空续取值，否则为 `null`。用返回的 cursor 连同相同的筛选条件和 `limit` 再次请求，结果会续在上一页之后，不重不漏。

cursor 是不透明令牌，仅对当前进程和相同筛选条件有效，不承诺重启后仍然可用；伪造、损坏或条件不符的 cursor 会被拒绝。

#### 列表请求错误

以下情况均返回 HTTP 400（错误码 `invalid_request`），且不改变任何资源：

- 未知或重复的查询参数；
- 空的 `category`/`name` 条件、非法类别、格式错误的 `digest`；
- `limit` 不是十进制正整数或超出 1–100 范围；
- cursor 伪造、损坏或与当前筛选条件、`limit` 不符。

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
- 当前公开业务接口为健康检查和上述资源登记/查询接口；资源数据仅存于进程内存，不承诺跨进程或重启后的保存。

