# Ethan2258 Rules

[![Update rules](https://github.com/Ethan2258/rules/actions/workflows/update-rules.yml/badge.svg)](https://github.com/Ethan2258/rules/actions/workflows/update-rules.yml)
[![Validate repository](https://github.com/Ethan2258/rules/actions/workflows/validate.yml/badge.svg)](https://github.com/Ethan2258/rules/actions/workflows/validate.yml)

为 sing-box 和 Egern 自动维护的精简规则集，每 3 小时同步一次上游。

## 规则集

| 规则集 | 内容 | 类型 | sing-box | Egern |
| --- | --- | --- | --- | --- |
| NodeSeek | NodeSeek 相关域名 | 域名 | [SRS](https://raw.githubusercontent.com/Ethan2258/rules/main/Nodeseek.srs) | [YAML](https://raw.githubusercontent.com/Ethan2258/rules/main/Nodeseek.yaml) |
| WebRTC | WebRTC STUN/TURN 服务器域名 | 域名 | [SRS](https://raw.githubusercontent.com/Ethan2258/rules/main/Webrtc_domain.srs) | - |
| Telegram SG | Telegram 新加坡网段 | IP | [SRS](https://raw.githubusercontent.com/Ethan2258/rules/main/TelegramSG.srs) | - |
| Telegram NL | Telegram 荷兰网段 | IP | [SRS](https://raw.githubusercontent.com/Ethan2258/rules/main/TelegramNL.srs) | - |

规则数、文件大小和 SHA-256 见[产物清单](.github/rule-artifacts.json)。无法直连 GitHub 时，可把链接前缀换成 `https://cdn.jsdelivr.net/gh/Ethan2258/rules@main/`（CDN 有缓存，更新会稍有延迟）。

## sing-box

以下写法适用于 sing-box 1.14+（`download_detour` 已弃用，改用 `http_clients`）：

```json
{
  "http_clients": [
    { "tag": "rule-download", "detour": "proxy" }
  ],
  "route": {
    "rule_set": [
      {
        "type": "remote",
        "tag": "nodeseek",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/Ethan2258/rules/main/Nodeseek.srs",
        "http_client": "rule-download",
        "update_interval": "3h"
      },
      {
        "type": "remote",
        "tag": "telegram-sg",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/Ethan2258/rules/main/TelegramSG.srs",
        "http_client": "rule-download",
        "update_interval": "3h"
      }
    ],
    "rules": [
      { "rule_set": "nodeseek", "action": "route", "outbound": "proxy" },
      { "rule_set": "telegram-sg", "action": "route", "outbound": "proxy" }
    ]
  }
}
```

把 `proxy` 换成自己的出站标签；1.14 以前的版本删掉 `http_clients` 和 `http_client` 即可。

## Egern

```yaml
rules:
  - rule_set:
      match: https://raw.githubusercontent.com/Ethan2258/rules/main/Nodeseek.yaml
      policy: DIRECT
      update_interval: 10800
```

`policy` 换成需要的策略（如 `DIRECT` 或 `PROXY`）。

## 更新机制

- 每 3 小时自动检查上游，也可[手动运行](https://github.com/Ethan2258/rules/actions/workflows/update-rules.yml)；内容有变化时才会提交。
- 来源：NodeSeek 跟随 MetaCubeX，WebRTC 来自 MeALiYeYe，Telegram SG/NL 来自 Kelee 并对照 Telegram 官方 CIDR 核验。
- 规则会先规范化、去重；遇到非法记录、规则数过少、网段越界或冲突时中止更新，保留上一版。
- SRS 由最新版 sing-box 编译后反向解码核对；[验证工作流](https://github.com/Ethan2258/rules/actions/workflows/validate.yml)检查 YAML、SRS、产物清单和 README 链接。

## 许可

脚本和工作流以 [GPL-3.0](LICENSE) 发布。规则数据来自上游，版权归原作者：[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)（GPL-3.0）、[MeALiYeYe/ProxyConfigFiles](https://github.com/MeALiYeYe/ProxyConfigFiles)、[Kelee](https://kelee.one) 及其镜像，Telegram 网段核验使用 [Telegram 官方 CIDR](https://core.telegram.org/resources/cidr.txt)。

## 图标

NodeSeek：[SVG](nodeseek.svg) · [PNG](nodeseek.png)
