# Firezone 防火墙规则冲突检测 / 设备组优先级 — 验收说明

运维反馈的「规则看着在、实际不生效」，根因是冲突规则被写进同一个键值结构，
后写入的规则静默覆盖前者。本次新增了一个显式的规则解析/下发内核：

- **冲突检测 + 显式报错**：同优先级下、匹配范围相交且动作相反（`allow` vs `deny`）
  的规则判定为硬冲突，返回全部冲突明细；下发入口直接拒绝，不产生任何 gateway 报文。
- **按设备组的优先级**：`DeviceGroup.priority` 数值越大优先级越高。不同优先级的
  相交冲突不再是错误，而是由高优先级规则决定，低优先级规则标记为 `shadows`。
  高优先级既可以是 `deny` 覆盖低优先级 `allow`，也可以是 `allow` 覆盖低优先级 `deny`。
- **与现有 gateway 兼容**：解析结果投影成 connlib 现有的 `Filter` 线格式
  （`protocol` / `port_range_start` / `port_range_end`，ICMP 为 `{"protocol":"icmp"}`），
  并复用现有 `allow_access` / `reject_access` 事件，**不需要改动已上线 gateway**。

## 一条命令验收

```bash
bash artifacts/run-firewall-rules-acceptance.sh
```

脚本零外部依赖：用纯 `rustc` 编译**真实的** gateway 侧核心
`rust/gateway/src/firewall_rules.rs`，先跑内联单测，再跑三种组配置 + 冲突拒绝的
41 项断言，并写出机器可读证据：

- `artifacts/firewall-rules-acceptance.json`（`"status": "passed"`）

如果环境里有可用的 `elixir`，脚本还会额外运行 Elixir 控制面的同构验收
`artifacts/firewall_rules_acceptance.exs`；没有则跳过（Rust 验收始终是权威结论）。

在装有完整依赖与 Postgres 的开发环境，也可以运行 ExUnit：

```bash
cd elixir
mix test test/portal/firewall_rules_test.exs
```

（仓库的 `test/test_helper.exs` 会走 Ecto Sandbox，因此完整 `mix test` 需要常规
开发数据库；该测试本身是纯内核测试，不使用 `DataCase`。）

Gateway 线格式还有一个**真实反序列化兼容测试**：它把本引擎投影出的 JSON 喂给
gateway 实际使用的 `tunnel_proto::messages::Filter` 反序列化并逐值比较。

```bash
cd rust
cargo test -p tunnel-proto --test firewall_rule_wire_compat
```

该测试 4 个用例（连同内联核心测试共 9 项）全部通过；同 crate 既有 filter 单测
（`cargo test -p tunnel-proto --lib filter`，25 项）也保持绿色。

## 三种组配置（生效规则与预期一致）

生效顺序为：优先级降序 → CIDR 前缀更长（更具体）→ 端口范围更窄 → 规则 ID。
同优先级且相交但动作相同不算冲突（合并语义一致）。

1. `single_group_specificity` — 单个 `office(priority=10)` 组。
   - 预期生效顺序：`allow-bastion-ssh`(/32:22) → `allow-internal-all-tcp`(10/8 全 TCP)
     → `allow-web-https`(:443)。
   - 抽测：`10.0.0.5:22 allow`、`10.1.2.3:8080 allow`、公网:443 `allow`、
     公网:22 `deny`、UDP/53 `deny`。
2. `tiered_priority_override` — `standard(10)` + `hardened(100)`，设备同时在两组。
   - 预期生效顺序：`hard-allow-bastion` → `hard-deny-web` → `std-allow-web` → `std-deny-ssh`。
   - 抽测：任意地址:443 被高优先级 `hard-deny-web` 拒；`10.0.0.5:22` 被高优先级
     `hard-allow-bastion` 放行（压过低优先级 `std-deny-ssh`）；`10.0.0.6:22` 仍拒绝。
   - gateway 投影：`10.0.0.5` 的 filters 恰为
     `[{"protocol":"tcp","port_range_start":22,"port_range_end":22}]`；
     `10.0.0.6` 无任何 allow filter，下发 `reject_access` 而不是 `filters: []`。
3. `three_group_merge` — `baseline(0)` + `engineering(50)` + `sre(80)`。
   - 预期生效顺序：`sre-deny-registry-prod`(/24:5000) → `sre-allow-ssh`(10/8:22)
     → `eng-registry`(10.20/16:5000) → `base-dns`(udp/53) → `base-ntp`(udp/123)；
     被 `enabled:false` 停用的 `eng-disabled-tailnet` 不出现。
   - 抽测：`10.20.1.10:5000 deny`（SRE 把生产 /24 从 registry 放行里抠掉）、
     `10.20.2.10:5000 allow`、`10.0.0.9:22 allow`、`11.0.0.9:22 deny`、
     UDP/53 `allow`、:9999 `deny`（停用规则缺席）。

## 冲突配置必须拒绝下发

下列配置在 `resolve` 阶段返回 `ConflictError`（含全部 `rule_a/rule_b/group/priority/reason`），
在 `dispatch` 阶段返回 `DispatchRejection`，且**不会**构造成功回执或 `allow_access` 报文：

- `cross_group_equal_priority`：`a`/`b` 两组同为 priority 50，
  `allow-db`(10.1.2.0/24:5432) 与 `deny-db`(10.1.2.3/32:5432) 相交且动作相反。
- `same_group_exact_opposites`：同一 `net` 组内 `allow-ssh`/`deny-ssh` 完全同匹配器。
  旧的 map 写入会静默留下最后一条（验收里用 `BTreeMap` 复现了 “last wins” 前提），
  现在必须报错。
- `overlapping_port_ranges`：同为 priority 20 的 `allow-low-ports`(tcp/1-1024) 与
  `deny-ssh`(tcp/22) 在 22 端口相交。

对照组 `disjoint same-priority`：同优先级但匹配器不相交（allow:443 vs deny:22）
**不**误报冲突。

## Gateway 兼容性说明（关键不变量）

connlib 的 `FilterEngine::new(&[])` 把**空 filter 列表解释为 `PermitAll`**。因此
「全部拒绝」不能投影成 `filters: []` 放在 `allow_access` 上，否则旧 gateway 会
fail-open。本实现：

- 对仍有放行端口/协议的目标，输出与 `rust/libs/connlib/tunnel-proto/src/messages.rs`
  中 `Filter` 完全一致的 JSON（按最大连续端口段合并）；
- 对完全拒绝的目标，下发既有的 `reject_access`（或不下发 `allow_access`），
  由 gateway 既有的授权/丢弃路径处理。

## 代码位置

- Elixir 控制面内核（下发前校验/解析/投影，权威实现）：
  `elixir/lib/portal/firewall_rules.ex`
- ExUnit：`elixir/test/portal/firewall_rules_test.exs`（9 个测试）
- Rust/gateway 侧零依赖语义内核 + 内联单测：
  `rust/gateway/src/firewall_rules.rs`（已在 `rust/gateway/src/main.rs` 以纯增量模块挂入）
- 真实 `Filter` 反序列化兼容测试：
  `rust/libs/connlib/tunnel-proto/tests/firewall_rule_wire_compat.rs`
- 验收运行器（真实编译 Rust 内核）：`artifacts/firewall_rules_acceptance.rs`
- Elixir 同构验收：`artifacts/firewall_rules_acceptance.exs`
- 一键脚本与证据：`artifacts/run-firewall-rules-acceptance.sh`、
  `artifacts/firewall-rules-acceptance.json`

## 接入真实下发路径的建议位置

在 portal 向 gateway push `allow_access` 之前
（`elixir/lib/portal_api/gateway/channel/shared.ex` 的
`handle_info({:allow_access, ...})` / 现有 `push(socket, "allow_access", ...)`），
先调用 `Portal.FirewallRules.dispatch/1`：

- `{:ok, receipt}`：用 `receipt.destinations[*].message` 对应的既有事件下发；
- `{:error, %Portal.FirewallRules.DispatchRejection{conflicts: conflicts}}`：
  记录/上报显式错误并中止本次下发，不写 gateway。

设备组优先级可直接取自组上的整型 `priority` 字段；缺省为 `0`，因此未配置优先级的
存量组彼此同层，行为退化为「同层相反相交即报错」，不会再静默覆盖。
