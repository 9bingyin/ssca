# ssca

`ssca` 是一个基于 Mihomo/ClashMeta 节点模型的订阅转换服务。

当前支持输出：

- Mihomo YAML
- v2rayN/base64 订阅
- sing-box JSON

## 配置目录

服务按配置目录读取固定文件名。默认配置目录是 `data`。

```text
data/
  nodes.yaml       # 节点列表
  profile.ini      # 规则集与策略组定义
  mihomo.yaml      # Mihomo 模板
  sing-box.json    # sing-box 模板
```

`profile.ini` 中的远程规则会在构建时下载并展开。

## 启动

使用默认目录 `data`：

```bash
bun run src/index.ts
```

指定配置目录：

```bash
bun run src/index.ts ./data
```

或：

```bash
bun run src/index.ts --config-dir ./data
```

指定监听地址和缓存时间：

```bash
bun run src/index.ts ./data --listen 127.0.0.1:3000 --cache-ttl 300
```

## HTTP API

服务只提供一个接口：

```text
GET /pull
```

### 输出 Mihomo

```bash
curl 'http://127.0.0.1:3000/pull?target=mihomo'
```

### 输出 v2rayN/base64

```bash
curl 'http://127.0.0.1:3000/pull?target=base64'
```

### 输出 sing-box

```bash
curl 'http://127.0.0.1:3000/pull?target=sing-box'
```

### 自动识别

```bash
curl 'http://127.0.0.1:3000/pull?target=auto'
```

`auto` 会根据 `User-Agent` 判断目标格式；无法识别时默认输出 Mihomo。

## sing-box 转换说明

sing-box 输出会使用 `sing-box.json` 作为模板，并覆盖/生成：

- `outbounds`
- `endpoints`
- `route.rules`
- `route.final`
- `route.rule_set`

规则转换会尽量保持 Mihomo 规则顺序。相邻且同类型、同目标的规则会合并到同一个数组字段中，例如连续的 `DOMAIN-SUFFIX` 会合并为一个 `domain_suffix` 数组。

sing-box 1.13 已移除旧的 `geoip`/`geosite` 数据库规则，因此当前处理方式：

- `GEOIP,LAN` 转为 `ip_is_private: true`
- 其他 `GEOIP` 转为 MetaCubeX `geoip/*.srs` 远程规则集
- `GEOSITE` 转为 MetaCubeX `geosite/*.srs` 远程规则集

## 校验

运行测试：

```bash
bun test
```

运行 TypeScript 类型检查：

```bash
bunx tsc --noEmit
```

校验生成的 sing-box 配置：

```bash
sing-box check -c /path/to/sing-box.json
```
