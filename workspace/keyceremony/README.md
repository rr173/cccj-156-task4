# Key Management Ceremony Orchestration System

编排**根密钥全生命周期仪式**的系统：生成（GENERATE）、轮换（ROTATE）、
备份/份额恢复（BACKUP）、销毁（DESTROY）。每次仪式都强制固定参与角色、
门限份额、设备远程证明和严格的操作顺序；任何单人都无法重建密钥。

纯 Python 标准库实现（无第三方依赖），包含一个 RFC 8032 Ed25519 的独立实现。

---

## 1. 它保证什么

| 需求 | 实现方式 |
|---|---|
| **固定参与角色** | 四种固定角色：`ROOT_OWNER`（安全负责人）、`KEY_STEWARD`（HSM 托管员）、`WITNESS_SHAREHOLDER`（独立见证人）、`ENCLAVE_OPERATOR`（签名飞地操作员）。策略创建后不可变，仪式打开时冻结快照。任何单个组织角色凑不齐门限（策略校验强制）。 |
| **门限份额** | Feldman 可验证 Shamir 秘密分享（默认 3-of-4），份额域 = MODP-14 安全素数群的素数阶子群（`(q-1)/2` 阶），承诺 `C_j = g2^coeff_j`。每台设备独立验证自己的份额 `g2^s_i == Π C_j^(i^j)` 后才允许确认。 |
| **任何单人不能重建密钥** | 编排器在 GENERATE/ROTATE 中**从不接触份额明文**：多项式在编排端生成后，份额用各设备的封装公钥（素数子群 KEM + HKDF + HMAC AEAD，绑定 `仪式ID|设备ID` 上下文）逐个密封投递；确认只需设备签名声明 VSS 校验通过。签名种子只从同一常数项派生，私钥材料用服务主包装密钥单独封存。 |
| **设备证明** | 每台设备有身份密钥（Ed25519）、封装密钥（MODP）和软件度量（SHA256）。仪式先颁发挑战随机数，设备对 `(挑战, 当前度量, 封装公钥, 时间戳)` 签名报价；编排器校验签名、度量与注册值一致、封装公钥与注册一致、时间窗、子群成员关系，然后才投递份额。 |
| **操作顺序** | 严格阶段机：`OPEN → ATTESTED → DELIVERED → CONFIRMED → COMMIT → COMPLETED`，不可跳级、不可回退；动作信封带设备签名与一次性 nonce（重放/同 nonce 换载荷分别报 `DUPLICATE_ACTION` / `REPLAY_DETECTED`）；仪式有截止时间，超时自动 ABORT。 |
| **开始后参与者/策略变化必须废弃本轮并保留审计** | 策略修订（`revise_policy`）会自动 ABORT 所有使用旧策略的打开中仪式；手动 ABORT 擦除本轮所有秘密态（待定签名种子、入站恢复份额、投递信封），但审计链完整保留，之后可开新一轮。 |
| **新旧密钥交接窗口并存** | ROTATE 先生成 `STAGED` 后继版本；发布是对“当前 ACTIVE 版本”的**比较并交换（CAS）**。发布成功后旧版本变 `RETIRING`，两者在交接窗口（策略 `handover_seconds`）内并存。同一 purpose 同时只允许一个打开的轮换仪式、至多一个 RETIRING 版本。 |
| **签名方只用已激活版本** | `sign` 只使用 `ACTIVE`；对 STAGED/RETIRING/DESTROYED 签名抛 `CONFLICT_STATE`。 |
| **验证方继续识别历史版本** | `verify` 遍历该 purpose 所有已识别版本（STAGED/ACTIVE/RETIRING/DESTROYED），返回匹配版本及其状态；销毁只擦除私钥材料，公钥/指纹/承诺永久保留用于历史签名验证。 |
| **份额丢失可恢复** | BACKUP 仪式：存活者用旧承诺验证并提交份额（至少门限份），在**同一常数项**上重新随机化多项式，向恢复后名册分发新份额；`C0` 不变（绑定同一密钥），高次承诺全部更新，签名身份不变。 |
| **参与者掉线/永久丢失可恢复** | GENERATE/ROTATE/DESTROY 要求**全员到场**，掉线则本轮无法推进（可废弃重开）。永久丢失参与者时 BACKUP 可声明 `lost_participants` + 1:1 同角色替补（必须 `replaces` 指定丢失槽位），存活者 ≥ 门限即可；丢失超过 `n-t` 则按策略不可恢复。 |
| **重复确认可恢复** | 同一设备重复确认是幂等拒绝（`DUPLICATE_ACTION`），不改变状态；相同动作信封重放也是幂等拒绝。 |
| **轮换发布竞态不产生两个当前密钥** | 所有状态变更在跨线程 RLock + 跨进程 flock + 状态加载均在锁内的事务中；发布走 CAS。并发发布者恰好一个成功，其余得到 `409 RACE_LOST`，可用新的当前指针安全重试（成功方重试为幂等）。每个 purpose 任何时刻恰有一个 ACTIVE。 |
| **可验证记录导出** | `export.json`（策略快照、全部公钥版本、仪式、设备、参与者、完整审计）+ `audit.txt` + `SHA256SUMS`。导出整体由服务身份 Ed25519 签名；审计条目逐条哈希链接（`SHA256(prev ‖ payload ‖ ts ‖ seq)`）并逐条服务签名。离线校验器检查签名、哈希链、密钥生命周期溯源（每个版本都来自 COMPLETED 仪式）、销毁版本无私钥、单一 ACTIVE 不变量、交接一致性。 |

审计中**只出现**承诺、公钥、身份与哈希，份额明文、签名种子、恢复入站份额从不入审计。

---

## 1b. 值班员会话与四眼审批（网页端 / 服务端门禁）

上面的密码学仪式保证「任何单人不能重建密钥」；HTTP 服务层另外强制「任何单人不能
独自改规则、停流程、发布或清除」。**编排库本身不加门禁**——脚本、恢复控制台和
测试直接 `import kc.ceremony.Orchestrator` 仍可全量调用；门禁只存在于
`kc.server` 的 HTTP 表面。

| 需求 | 实现方式 |
|---|---|
| **登录令牌绑定人员/职责/终端/证明时效** | 登录先颁发一次性挑战，注册终端用钱包身份密钥对 `(挑战, 实时度量, 封装公钥, 时间戳)` 报价；服务端校验签名、度量、封装公钥、时窗后才签发令牌。令牌记录 `participant_id·role·device_id·measurement·quote_ts·expires_at`；原始令牌不落盘（只存其哈希标识 `token_id`）。终端撤销立即吊销其上全部在线会话。 |
| **查询按职责放行** | `authz.READ_SCOPES`：owner/witness 可看审计与导出包，steward/operator 不可；设备动作（attest/receive/confirm/submit-share）还要求令牌**本人终端**，驱动他人终端返回 `403 FORBIDDEN`。 |
| **四类高危动作须四眼** | 修改规则（`POLICY_CHANGE`）、终止活动流程（`ABORT_ACTIVE`）、发布新代（`PUBLISH_GENERATION`）、清除退役材料（`PURGE_RETIRED`，即 DESTROY 的 commit）在 HTTP 端不能直接调用，返回 `422 PROTECTED_OPERATION`。流程：发起人 `POST /api/tickets` → **另一人员、另一终端、互补职责** `POST /api/tickets/approve`，批准与执行在同一把存储锁内原子完成。 |
| **冻结规范化载荷摘要 + 截止时间** | 授权单保存 `canonical(JSON)`（排序、压缩）载荷的 SHA256 摘要与 `deadline`；批准时重算摘要，不一致即 `409 PAYLOAD_DRIFT` 并关闭授权单。 |
| **重复提交返回原授权单** | 同操作+同摘要存在 OPEN/EXECUTED 授权单时直接返回原单（`duplicate:true`），不新建。 |
| **并发批准最多执行一次** | 批准临界区在跨线程/跨进程锁内；6 路并发批准恰好 1 路成功，其余 `TICKET_CLOSED`。 |
| **失效即关闭、不落半成品** | 令牌失效/到期、终端撤销、载荷漂移、职责冲突、目标状态变化都会关闭授权单（记录机读 `closed_reason`），执行器在变更前完成校验，授权单从不留下执行一半的效果。 |
| **重新登录后继续** | 同人员在**同一注册终端**重新证明换发新令牌（旧令牌置 SUPERSEDED）后，其在途授权单仍可被批准；若终端撤销或无后继会话则关闭。 |
| **撤回** | 发起人可撤回自己在途的授权单（他人撤回 `403`）。 |
| **网页展示与操作** | 控制台展示登录身份（人员/职责/终端/证明度量/令牌标识/到期）、按职责可执行动作（无权限按钮禁用）、授权单表（双方、摘要、截止、决策链、执行结果）；支持发起、批准、撤回及退出/重新登录。 |
| **导出与离线核验** | 导出包新增 `sessions`（仅 token_id 等，绝无原始令牌）与 `auth_tickets`：双方身份、双方令牌标识、冻结摘要、完整决策链、执行结果。离线核验器校验：批准人≠发起人、终端不同、职责互补且在允许矩阵内、摘要稳定、执行效果在密钥/仪式状态中可见、每个执行/关闭/撤回都有哈希链审计记录；删改任一处都会被服务签名、审计链或 `four_eyes_tickets_ok` 检出。 |

互补职责矩阵（`kc/authz.py`）：

| 操作 | 可发起职责 | 可批准职责 |
|---|---|---|
| POLICY_CHANGE | ROOT_OWNER | WITNESS_SHAREHOLDER |
| ABORT_ACTIVE | ROOT_OWNER / KEY_STEWARD / ENCLAVE_OPERATOR | WITNESS_SHAREHOLDER / ROOT_OWNER |
| PUBLISH_GENERATION | ENCLAVE_OPERATOR / KEY_STEWARD | ROOT_OWNER |
| PURGE_RETIRED | KEY_STEWARD / ENCLAVE_OPERATOR | WITNESS_SHAREHOLDER / ROOT_OWNER |

登录与会话接口：`POST /api/session/login-challenge`、`POST /api/session/login`、
`POST /api/session/relogin`、`POST /api/session/logout`、`GET /api/session/me`、
`GET /api/tickets`、`POST /api/tickets[/approve|/withdraw]`、
`POST /api/devices/revoke`。服务端令牌通过 `Authorization: Bearer …` 传递。

---

## 1c. 可反复执行的跨区域灾备演练（隔离重建 / 只读镜像 / 租约切换 / 证据档案）

在**不触碰生产密钥材料**的前提下，反复证明某个恢复点能够在隔离区域重建服务、
承接只读校验流量，并安全完成故障切换与回切。原有命令行库与线上接口完全兼容；
新能力位于独立模块（`kc/regions.py`、`kc/drills.py`、`kc/evidence.py`），
演练引擎从不解封根材料——只复制**已加密封装对象**的描述符与哈希。

| 需求 | 实现方式 |
|---|---|
| **方案修订号 / 乐观并发** | 方案（plan）按修订号保存；两个浏览器同时编辑时，落后提交收到 `409 REVISION_CONFLICT`，载荷带 `base_revision/current_revision/base_snapshot/current_snapshot` 双方差异，绝不覆盖新版本。扫描后再改方案，旧扫描立即作废（状态回到 `DRAFT`）。 |
| **演练专用短期凭据 + 命名空间** | 启动即生成一次性 `drk_…` 凭据（仅创建响应返回，之后不再出现）与 `drill-<id>` 命名空间；凭据 `writes_allowed:false`、`production_referenceable:false`、只绑定隔离目标区域；过期不可再激活，必须终止后新开演练。 |
| **启动前清单扫描 → 固定蓝图** | 扫描核对快照清单、逐对象哈希、依赖版本、目标容量、加密封装（根材料必须 `sealed` + `kc-aead-v1`）与目标隔离策略（`AIRGAPPED` + 强制 `drill-` 命名空间 + 禁用生产凭据）；任何一项失败抛 `422 PREFLIGHT_FAILED`（列出全部问题）且**不创建任何资源**。通过后冻结固定恢复蓝图（含源/目标 `config_seq`、快照清单哈希）。 |
| **源快照/目标配置/蓝图变化即作废** | 蓝图钉住源/目标 `config_seq` 与恢复点 `manifest_hash`；源快照或目标配置一旦 `update_config()`，`latest_valid_scan` 立即返回空，启动演练抛 `409 BLUEPRINT_STALE`。 |
| **分阶段、幂等、可续跑引擎** | 固定阶段 `PREPARE → COPY → REBUILD_INDEX → SHADOW_START → PROBES → READY`，每阶段落持久化检查点与确定性幂等键 `SHA256(drill|stage|blueprint)`。崩溃 / 节点迁移 / 重复启动后从最后一个**已确认**阶段继续；资源按幂等键只建一次，对象不重复计入（测试在三个阶段注入崩溃并真实落盘重开）。 |
| **只读观察窗口 + 对比器** | 限时窗口内按方案比例（按请求关联号确定性选取，可复现）镜像只读校验请求；对比器记录请求关联号、双侧结果哈希、延迟与差异类别（`RESPONSE_MISMATCH/LATENCY/TIMEOUT`）。 |
| **写请求始终留在生产** | `SIGN/GENERATE/ROTATE/DESTROY/REVOKE/POLICY_CHANGE` 等写操作即使携带伪造的 `mirror_to_shadow` 标记也被明确拒绝（`POLICY_VIOLATION`），永远只走生产。窗口外的强制镜像同样被拒绝（`DRILL_FROZEN`）。 |
| **差异容错额度：非负整数，原子累计，超额才停用** | 方案字段 `diff_threshold` 必须是**非负整数**（拒绝负值、布尔、浮点与数字字符串）。系统在跨线程/跨进程存储锁内**原子累计不一致次数**，同一请求关联号无论重放多少次只计一次；仅当累计数**大于额度**时才冻结旁路（额度 0＝首个不一致即冻结；1＝容忍一个、第二个冻结；3＝容忍三个、第四个冻结）。计数在并发校验、服务重启（持久化 + 旧记录从差异清单回填）与人工 `resume` 解除后保持连续且不重复；冻结记录保留触发停用的关联号、当时额度与累计数。页面、HTTP 返回（`tolerance{diff_threshold,mismatch_count,trigger_request_id}`）、`mirror-stats` 与证据档案给出完全一致的额度、当前计数与触发关联号；离线核验器检查计数连续、关联号不重复、冻结快照与差异记录一致。 |
| **带期限的单持有者租约** | 仅当全部探针通过且仍满足 RTO 才能 `acquire lease`；多控制实例并发恰好一个成功，其余 `409 LEASE_CONTENTION`。租约只接管**只读校验入口**（`read_only_verification_ingress`），生产写入口保持不变。 |
| **统一收敛的回切状态机** | 租约丢失（到期）、区域恢复、窗口关闭、人工回切全部收敛到同一 `FAILED_BACK` 状态；重复提交回切返回**原结果**（同一 `failed_back_at`，幂等标记）。 |
| **受阻、可续跑的清理** | 终止先撤凭据、再删隔离资源、最后封存证据；清理中断后可继续。仍有镜像流量（窗口开）、有效租约或未归档差异时禁止删除关键资源，抛 `409 CLEANUP_BLOCKED` 并明确列出阻塞项；归档差异 / 关窗 / 释放租约后续跑完成。 |
| **可验证证据档案** | 证据含恢复点清单、蓝图摘要、阶段检查点、探针输入输出摘要、镜像对比统计、租约历史、回切与清理结果；清单逐节哈希 + 整体 `manifest_hash` + 服务身份 Ed25519 签名。离线检查器重算对象哈希与阶段顺序，检出伪造恢复点、跳过探针、重复阶段、窗口外镜像、租约重叠与证据缺口；旧格式 `kc-drill-evidence-v1` 仍可读取（结构归一化后校验）。 |

演练接口（HTTP 层按职责放行；库 `DrillsManager` 直调不加门禁，与既有设计一致）：

```
POST /api/drill-regions/{define|put-object|recovery-point}   # 区域/恢复点建模
POST /api/drill-plans            # 创建，或带 plan_id+base_revision 修订
POST /api/drill-plans/{id}/scan  # 清单扫描 → 固定蓝图
POST /api/drill-plans/{id}/start # 发短期凭据+命名空间，建演练
POST /api/drills/{id}/{run-to-ready|window|mirror|resume}
POST /api/drills/{id}/{lease|failover-status|failback}
POST /api/drills/{id}/{archive-differences|terminate|cleanup}
GET  /api/drill-plans /api/drills /api/drills/{id}
GET  /api/drills/{id}/evidence
```

职责矩阵新增 `drill:plan/scan/run/mirror/lease/failback/terminate` 能力与
`drills` 读域：owner/steward/operator 可设计、扫描、驱动与清理；**租约获取
（接管只读入口）仅 ROOT_OWNER**；witness 可只读查看演练与证据。导出包
新增 `drill_plans/drills/drill_evidence/drill_regions`，离线校验器增加
`drill_evidence_ok` 检查项。证据/审计中只出现哈希、封装描述符与公开标识，
短期凭据明文、根材料明文从不入库、不入审计（扫描也不写敏感内容）。

---


## 2. 目录结构

```
kc/
  ed25519.py      纯 Python Ed25519（RFC 8032 向量验证）
  crypto.py       MODP-14 Feldman VSS、Shamir/Lagrange、KEM+AEAD 封装、HKDF、规范 JSON
  policy.py       固定角色、策略不可变快照、法定人数规则、阶段常量
  attestation.py  设备钱包（模拟 HSM）、注册记录、报价生成与校验
  ceremony.py     编排器：四仪式 × 六阶段状态机、恢复数学、CAS 发布
  directory.py    密钥版本目录：STAGED/ACTIVE/RETIRING/DESTROYED、签名与验证
  storage.py      文件锁（跨线程可重入 RLock + flock）、原子状态、哈希链审计
  regions.py      区域/命名空间/容量/隔离策略/恢复点清单（跨区域演练的区域模型）
  drills.py       灾备演练：修订方案、清单蓝图、分阶段幂等引擎、镜像对比、租约、受阻清理
  evidence.py     演练证据档案：签名清单 + 离线检查（伪造/跳探/重阶段/窗口外镜像/租约重叠）
  sessions.py     终端证明登录：挑战/报价、绑定人员·职责·终端·时效的会话令牌
  authz.py        四眼授权单：冻结摘要/截止、互补职责矩阵、决策链、单次执行
  console.py      设备侧代理：证明→取件→验份额→签名确认
  fleet.py        模拟设备机群（每台设备一个 0600 钱包文件）
  export.py       记录导出与离线验证（含会话/四眼授权链核验）
  server.py       HTTP API + 控制台（ThreadingHTTPServer，会话+四眼门禁）
  console.html    仪式控制台 UI（登录身份/可执行动作/授权单面板）
  bootstrap.py    一键引导固定角色/设备/策略
  verify_export.py 导出/离线校验 CLI
tests/
  smoke_e2e.py        端到端冒烟
  test_ceremonies.py  21 个场景测试（证明、顺序、恢复、竞态、销毁、篡改检测…）
  test_edge.py        8 个边界测试（超时、VSS 失败、吊销、策略护栏、多用途、并发）
  test_authz.py       30 个会话/四眼测试（绑定、门禁、漂移、截止、撤销、并发单次、篡改导出）
  test_drills.py      37 个跨区域灾备演练场景（修订冲突、蓝图失效、分阶段崩溃续跑、
                      流量镜像隔离、差异冻结、租约竞争、回切幂等、受阻清理、证据篡改）
  http_e2e.py         HTTP 全流程含登录门禁、四类授权单、6 路并发批准、库直调不受限
  drill_http_e2e.py   演练 HTTP 全流程（区域/修订/扫描/续跑/镜像/冻结/租约/受阻清理/证据）
```

## 3. 快速开始

```bash
# 1) 引导：4 个固定角色 + 设备钱包 + 3-of-4 策略
python3 -m kc.bootstrap --root ./kc-data
# 2) 启动控制台/API
python3 -m kc.server --root ./kc-data --port 8080
# 浏览器打开 http://127.0.0.1:8080/
```

控制台按钮对应一次仪式一步（每台设备独立证明、取件、验份额、确认）。

## 4. 一次完整仪式的操作顺序

GENERATE / ROTATE（DESTROY 无投递阶段；BACKUP 见第 6 节）：

1. `POST /api/ceremonies/open` — 冻结策略快照；同 purpose 不允许第二个打开中仪式。
2. 每台设备依次 `POST /api/ceremonies/{id}/attest`（全员，因为这三类仪式要求全员）。
   最后一份证明成功后阶段自动进入 `ATTESTED`，编排器随即分份并进入 `DELIVERED`。
3. 每台设备 `receive`：拉取**仅发给自己**的密封信封 → 设备内解封 → 对照公开
   Feldman 承诺验证份额。失败则设备拒绝确认（`vss_ok=false` 会被策略拒绝）。
4. 至少 **门限个不同参与者**确认，且**必须含 ROOT_OWNER**；到齐后进入 `CONFIRMED`。
   重复确认返回 `DUPLICATE_ACTION`，不影响继续。
5. `commit`：
   - GENERATE/ROTATE 物化密钥版本（GENERATE 直接 ACTIVE；ROTATE 先 STAGED）；
   - DESTROY 零化目标 RETIRING 版本的私钥材料。
6. ROTATE 额外 `publish`（带 `expected_active` 的 CAS）：旧版 → RETIRING，
   新版 → ACTIVE，交接窗口开始。竞态失败返回 `RACE_LOST`，刷新当前指针重试。
   **HTTP 端的 publish 必须经 PUBLISH_GENERATION 四眼授权单**（见第 1b 节）；
   库直调 `Orchestrator.publish_rotation` 不受此限。

## 5. 签名测试接口

```bash
curl -s -XPOST localhost:8080/api/sign   -d '{"purpose":"root-signing","message":"hello"}'
curl -s -XPOST localhost:8080/api/verify -d '{"purpose":"root-signing","message":"hello","sig":"..."}'
```

- 签名响应带 `version_id/version/status/fingerprint`；只有 ACTIVE 可签。
- 验证接受该 purpose 全部历史版本，返回匹配版本状态（`active:true/false`）；
  对 DESTROYED 版本的历史签名依然返回 `valid:true,status:DESTROYED`。

## 6. 份额丢失 / 参与者丢失恢复

```jsonc
// 打开 BACKUP：bruno 永久丢失，finn 以同角色替补
POST /api/ceremonies/open
{"kind":"BACKUP","policy_id":"pol-root-v1","purpose":"root-signing","actor":"alice",
 "lost_participants":["bruno"],
 "replacement_specs":[{"participant_id":"finn","role":"KEY_STEWARD",
                       "device_id":"dev_finn","replaces":"bruno"}]}
```

- 恢复名册（存活者+替补）全员 attest；
- 仅**存活者**（≥ 门限）用各自持有的旧仪式份额 `submit-share`，编排端逐份用
  当前密钥承诺校验，入站份额仅以服务包装密文短暂存放、完成后清除；
- 门限到达后在同一秘密上重建并重新分份（新随机多项式）；
- 恢复名册全员 receive、验份额、门限确认（含 owner）→ commit；
- 密钥 id 与签名公钥不变，承诺列更新、`share_meta` 指向新持有者。

纯粹的份额丢失（人还在、HSM 被擦）则 `lost_participants` 留空，全员提交/领取即可。

## 7. 可验证记录导出

```bash
# 从状态目录导出
python3 -m kc.verify_export --from-store ./kc-data --outdir ./export
# 在任意机器上离线核验（不需要状态目录或任何秘密）
python3 -m kc.verify_export ./export/export.json
# 也可 GET /api/export 获取签名包；GET /api/audit 查看链验证结果
```

输出 `[PASS] bundle_signature_ok / audit_chain_ok /
single_active_per_purpose / handover_consistent`。

## 8. HTTP API 摘要

除 `/health`、控制台页面和两个登录接口外，所有 API 都需要
`Authorization: Bearer <token>`（或 `X-Session-Token`）；令牌来自终端证明登录。
设备类接口要求令牌绑定的终端与请求的 `device_id` 相同。

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/session/login-challenge` `/api/session/login` | 终端证明登录（无需令牌） |
| POST | `/api/session/relogin` `/api/session/logout` | 同终端重新登录续作 / 登出 |
| GET | `/api/session/me` `/api/tickets` | 当前身份/可执行动作 / 授权单列表 |
| POST | `/api/tickets` `/api/tickets/approve` `/api/tickets/withdraw` | 发起 / 批准执行 / 撤回授权单 |
| POST | `/api/devices/revoke` | 撤销终端（吊销其会话、关闭其在途授权单，仅 owner） |
| POST | `/api/participants` | 注册参与者并配发设备钱包（仅 owner） |
| POST | `/api/policies` | **已改为四眼**：直接调用返回 `PROTECTED_OPERATION`，走 POLICY_CHANGE 授权单 |
| POST | `/api/ceremonies/open` | 开仪式（按职责放行） |
| POST | `/api/ceremonies/{id}/attest` | 设备证明（仅本人终端） |
| POST | `/api/ceremonies/{id}/receive` | 取密封份额（仅本人终端） |
| POST | `/api/ceremonies/{id}/confirm` | 门限确认（仅本人终端） |
| POST | `/api/ceremonies/{id}/submit-share` | BACKUP 存活者提交旧份额（仅本人终端） |
| POST | `/api/ceremonies/{id}/commit` | 法定人数齐备后提交（DESTROY 走 PURGE_RETIRED 授权单） |
| POST | `/api/ceremonies/{id}/publish` | **已改为四眼**：PUBLISH_GENERATION 授权单批准时执行 CAS |
| POST | `/api/ceremonies/{id}/abort` | **已改为四眼**：ABORT_ACTIVE 授权单 |
| POST | `/api/sign` `/api/verify` | 签名测试接口（签名按职责放行） |
| GET | `/api/keys` `/api/ceremonies` `/api/audit` `/api/export` | 只读视图（审计/导出仅 owner、witness） |

> 注意：这些门禁只在 HTTP 层。直接使用 `Orchestrator`（库）时，
> `create_policy/revise_policy`、`abort`、`publish_rotation`、`commit(DESTROY)`
> 等全部保持原样可用。

错误码：`POLICY_VIOLATION(422)`、`CONFLICT_STATE/DUPLICATE_ACTION/REPLAY_DETECTED/RACE_LOST(409)`、
`ATTESTATION_FAILED/AUTH_FAILED(401)`、`FORBIDDEN(403)`、
`PROTECTED_OPERATION(422)`、`TICKET_CLOSED/PAYLOAD_DRIFT/COMPLEMENTARY_DUTY_CONFLICT/TARGET_STATE_CHANGED(409)`、
`NOT_FOUND(404)`、`TAMPER_DETECTED(409)`。

## 9. 持久化与并发模型

- `state.json`：所有可变记录，锁内加载、原子临时文件 rename 落盘。
- `audit.log`：每行一个 JSON，追加写 + `fsync`，哈希链 + 服务签名。
- `.lock`：跨进程 flock；进程内按数据目录共享一把可重入 RLock。
  HTTP 服务多线程、多进程部署都被串行化，且每个请求在**锁内**读取最新状态。
- 重启后状态、密封私钥、审计链均可恢复；`tests/smoke_e2e.py` 覆盖重启验证。

## 10. 密码学说明（生产化注意）

本实现是**完整可运行的参考实现**，数学与协议真实（Ed25519 通过 RFC 8032 向量、
Feldman VSS 逐份验证、安全素数群子群一致性）。生产部署时建议：

- 份额多项式生成与签名运算放入真实 HSM/飞地；本系统的 `DeviceWallet` 是其软件模型；
- 用 FIPS 验证的模块化指数实现（当前为教学级纯 Python 2048 位运算）；
- 服务主包装密钥换成 KMS/HSM LMK；设备证明对接 TPM Quote/Nitro/TPM 证书链；
- 生产链路建议在终端证明登录之外再加 mTLS/传输加密。HTTP 层已实现终端证明
  会话（人员·职责·终端·时效绑定）、按职责放行与四眼授权单；库调用面按设计
  保持不加门禁（供受信恢复/自动化通道使用），生产暴露该面时应置于受控网络或
  再加一层调用方鉴权。

## 11. 测试

```bash
python3 tests/smoke_e2e.py
python3 -m unittest tests.test_ceremonies tests.test_edge tests.test_authz tests.test_drills -v
python3 tests/http_e2e.py 8211          # 登录门禁 + 四类四眼授权单 + 6 路并发批准 + 库直调
python3 tests/drill_http_e2e.py 8212    # 跨区域灾备演练 HTTP 全流程
# 或一次跑完：
./run_tests.sh 8301 8302
```

## 12. 一次四眼操作的示例（发布新代）

```bash
# 发起人 diego（ENCLAVE_OPERATOR，终端 dev_diego）先登录
curl -s -XPOST localhost:8080/api/session/login-challenge -d '{"device_id":"dev_diego"}'
TOK_D=$(curl -s -XPOST localhost:8080/api/session/login -d '{"device_id":"dev_diego"}' \
        | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
# 冻结规范化载荷 + 截止时间，创建授权单（重复提交返回原单）
T=$(curl -s -XPOST localhost:8080/api/tickets -H "Authorization: Bearer $TOK_D" \
    -d '{"operation":"PUBLISH_GENERATION",
         "payload":{"ceremony_id":"cer_xxx","expected_active":"kv_old"}}')
# 批准人 alice（ROOT_OWNER，另一人员、另一终端 dev_alice、互补职责）登录并批准；
# 批准瞬间在锁内做目标预检并执行 CAS，最多执行一次。
curl -s -XPOST localhost:8080/api/tickets/approve -H "Authorization: Bearer $TOK_A" \
    -d '{"ticket_id":"auth_..."}'
```

目标已被他路（含库直调）推进时，预检关闭授权单并返回 `TARGET_STATE_CHANGED`，
不会产生半成品；用最新状态创建新授权单即可。
