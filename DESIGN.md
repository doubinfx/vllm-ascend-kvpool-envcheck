# vLLM-Ascend kvpool 环境检测工具设计

版本：v14.1.1  
规则事实源：`rules.json`（schema `7.1`）  
结果协议：`13.1`

本文只描述当前实现的边界、判定原则、输出协议和维护方法。规则具体内容以 `rules.json` 为准，避免文档与代码各维护一份规则。

## 1. 边界与输入契约

- 工具只支持在 vLLM-Ascend Docker 容器内运行；不联网、不安装依赖、不升级 host、不修改网络配置，默认只读。
- 支持的组合由 `rules.json` 的 `supported_hardware`、`supported_backends`、`supported_link_types` 和 `supported_deployment_modes` 提供。当前硬件为 A2/A3，后端为 memcache/mooncake，链路为 roce/hccs，部署模式为 single-node/multi-node。
- `--hardware` 必须在目录支持范围内，且必须与当前容器识别到的硬件完全一致；A2 识别 910B 家族，A3 识别 `Ascend910` 且每张逻辑卡包含 2 个 die。
- A2 只允许 `--link-type roce`；A3 根据 `--link-type` 选择 RoCE 或节点内 HCCS 检查。`--deployment-mode` 影响多节点专属场景。
- `--managed-memory-mb` 表示后端纳管内存总量，按全局容量比较，不按卡、die 或 NUMA 节点均摊。
- `--ssd-offload` 仅启用 SSD Offload 专属检查，并要求显式提供 `--ssd-path`。

## 2. 架构与规则模型

运行流程为：加载并校验目录 → 校验输入与硬件 → 生成适用规则和 probe 计划 → 在 Docker 内执行探测 → 按规则独立判定 → 可选执行已授权本地修复 → 生成一次性结果模型。

规则至少包含 `id`、`problem`、`impact`、`hardware`、`backends`、`scope`、`blocking`、`probe`、`evaluator`、`parameters`、`evidence_method` 和 `remediation`。可选 `link_types`、`deployment_modes`、`feature`、`exclude_feature` 用于限定适用范围。规则之间不引用其他规则 ID；软件兼容矩阵直接写在本规则参数中，避免隐藏依赖。

`scope=docker` 表示在容器内执行；无法在容器内取得证据的场景不伪装为已检测。人工确认场景使用 `MANUAL_REQUIRED`，不适用场景使用 `NOT_APPLICABLE`，不执行场景使用 `NOT_EXECUTED`。这些状态都进入同一 `check_results` 模型。

## 3. 检测策略

### 内存

- A3 固化用户指导文档提供的 `artifacts/mem_scan.py` 原文，先以 1GB 粒度扫描，容量不足再以 2MB 粒度扫描；任一粒度达到目标即通过。
- A2 不运行扫描脚本，读取 `/proc/meminfo` 的 `Hugepagesize=2048kB` 和 `HugePages_Free`，以静态 2MB 大页总空闲容量与目标值比较。
- A3 的 `--fix` 仅在扫描完成但容量不足时尝试 Drop Cache 后复测；A2 静态大页不足不执行 Drop Cache。

### 版本与公共依赖

- CANN 统一要求 `>=9.1.0`。
- HDK-001 按硬件/后端矩阵判定：A2 两个后端最低 25.5；A3 memcache 最低 26.0；A3 mooncake 支持 25.5 兼容路径，但需同时满足独立的 Mooncake 软件依赖，26.0 及以上为主路径。
- KERNEL-001 只针对 A3 + memcache 多节点；单节点返回 `NOT_APPLICABLE`，不阻塞单节点部署。
- Docker 公共依赖检查设备、`npu-smi`、Davinci 设备、驱动目录，以及 `/etc/hccn.conf` 或可执行 `hccn_tool` 至少一个入口。

### A3 节点内互联

`HCCS-001` 检查全部可见 card/die 的 SIO/HCCS 拓扑、health、lane 完整性和速率；`HCCS-002` 在静态状态正常且 NPU 空闲时，使用固化的 HCCL all-to-all 数据正确性测试，并比较本次 retry/error 增量。两者均不覆盖跨主机通信或灵衢 CC 版本。

### 参数面 RoCE

`ROCE-001` 检查全部可见 NPU 端口的 IP、掩码、MTU、Link 和 health 等静态状态；`ROCE-002` 在静态通过后，对当前主机全部有向 NPU 卡对执行设备侧 `hccn_tool` ping，并检查丢包和本次错误计数增量。两项均只覆盖当前主机设备侧，不代表跨主机业务拓扑已验证。

### 其他场景

`LINGQU-001` 仅适用于 A3 + HCCS + multi-node，版本无法在容器内自动确认，结果要求运维登录 1520 或 BMC 确认。软件包、glibc 和 SSD 路径检查只在对应后端或显式启用功能时适用。

## 4. 输出、修复与日志

工具一次检测只构建一个结果模型；TEXT 是该模型的人类可读投影，JSON 是完整机器可读事实源，两者共享 `run_id`、输入参数、汇总结论和每个场景状态。

| 产物 | 用途 |
|---|---|
| `*.result.json` | 完整结构化结果、原始证据、修复动作和参考文档信息，供程序处理或归档 |
| `*.report.txt` | 面向使用者的环境检测报告，突出阻塞项、结论和建议 |
| 标准输出 | 未指定 `--output-dir` 时回显 TEXT 报告；指定目录时回显完成提示 |
| 标准错误 | 运行进度，仅包含输入校验和实际 probe 的开始、结束及耗时 |
| `DESIGN.md` | 当前实现与规则维护说明 |

指定 `--output-dir` 时生成 `kvpool_envcheck_<run_id>.result.json` 和 `kvpool_envcheck_<run_id>.report.txt`；未指定时不创建文件。有效入参统一记录在 `invocation.arguments`，包括 hardware、backend、managed memory、deployment mode、link type、SSD、fix、catalog、output-dir 和 progress。

`--fix` 即本地修复授权。当前只有 A3 MEM-001 支持 Drop Cache 后复测；其他需要 host、网络设备或镜像变更的动作只输出人工修复建议。修复前后汇总、动作状态和复测证据均保存在 `repair` 中。

## 5. 规则维护与参考资料

`rules.json` 是唯一规则事实源。维护规则后执行：

```bash
python3 kvpool_envcheck.py --validate-catalog
python3 kvpool_envcheck.py --list-rules
python3 kvpool_envcheck.py --describe-rule RULE-ID
python3 kvpool_envcheck.py --sync-panorama DESIGN.md
```

文档末尾的规则全景由 `--sync-panorama` 根据已校验的 `rules.json` 自动生成，不手工维护。规则新增、删除或修改后必须重新同步，避免留下旧场景、旧适用范围或旧修复建议。

参考手册链接、source commit、审视日期和内容 SHA256 固化在结果顶层 `reference_documents`；工具运行时不联网。

<!-- BEGIN GENERATED RULE PANORAMA -->

| 问题ID | 问题 | 检测定位 | 影响 | 检测证据 | 判定规则 | 修复方法 | 是否阻塞 | 适用硬件 | 适用后端 | 适用链路 | 适用部署 | 运行位置 | 实现状态 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| MEM-001 | 纳管内存检查未通过 | - | 后端无法确认并注册目标纳管内存容量。 | A3使用官方 mem_scan.py 按1GB、2MB粒度扫描；A2读取Hugepagesize=2048kB的静态大页空闲数量，并将全局可用容量与目标值比较 | `memory_scan` `{}` | 根据检测详情恢复扫描能力或释放内存后复测。 | 是 | A2,A3 | memcache,mooncake | all | all | docker | 已实现 |
| CANN-001 | CANN 版本低于 9.1.0 | - | 池化内存语义特性依赖不满足，kvpool 不可用。 | Docker 内 CANN Toolkit 安装信息和 ASCEND_TOOLKIT_HOME | `version_range` `{"value_key":"cann_version","operator":"lt","threshold":"9.1.0","unknown_status":"BLOCK"}` | 使用与硬件、镜像和发行版匹配的 CANN >=9.1.0 离线包重建/更新镜像后复测。 | 是 | A2,A3 | memcache,mooncake | all | all | docker | 已实现 |
| HDK-001 | HDK 版本不满足当前硬件和后端要求 | - | HDK 版本低于当前硬件和后端的最低要求，可能导致可管理内存不足或 kvpool 初始化失败。 | 读取 Docker 内可见的 npu-smi/driver version.info，并按 hardware/backend 选择最低 HDK 版本；A3 + mooncake 的 25.5 兼容路径同时要求 Mooncake 软件依赖满足版本要求 | `hdk_requirement` `{"requirements":[{"hardware":"A2","backend":"memcache","minimum":"25.5.0"},{"hardware":"A2","backend":"mooncake","minimum":"25.5.0"},{"hardware":"A3","backend":"memcache","minimum":"26.0.0"},{"hardware":"A3","backend":"mooncake","minimum":"25.5.0","preferred":"26.0.0","compatibility_dependency":"mooncake-transfer-engine-npu>=0.3.11.post1"}],"unknown_status":"BLOCK"}` | 将 host HDK 升级到检测详情要求的最低版本，更新 Docker 挂载后重启容器并复测。 | 是 | A2,A3 | memcache,mooncake | all | all | docker | 已实现 |
| KERNEL-001 | Linux kernel 版本低于 6.6.0 | - | 多节点部署时kvpool可能失效；单节点部署不受该依赖影响。 | 在 Docker 内执行 uname -r，读取容器所见的 host Linux kernel 版本 | `kernel_requirement` `{"threshold":"6.6.0","unknown_status":"BLOCK"}` | 在 host 维护流程升级 Linux kernel 到 >=6.6.0；升级完成后重建或重启容器并复测。 | 是 | A3 | memcache | all | multi-node | docker | 已实现 |
| LINGQU-001 | L1 1520 灵衢 CC 版本需人工确认 >= 1.5.0 | - | A3 + memcache/mooncake 场景可能建链失败，kvpool 失效。 | 无法自动检测到对应版本，需要通过运维登录L1 1520交换机或在BMC纳管界面确认版本是否满足要求 | `manual_confirmation` `{"required_confirmation":"无法自动检测到对应版本，需要通过运维登录L1 1520交换机或在BMC纳管界面确认版本是否满足要求"}` | 登录1520和在BMC纳管界面，先查看L1 1520 灵衢 CC 版本，低于 1.5.0 时由网络设备管理员升级。 | 是 | A3 | memcache,mooncake | hccs | multi-node | docker | 已实现 |
| HCCS-001 | A3 节点内 SIO/HCCS 链路未就绪 | A3 NPU 节点内互联；卡内 SIO 与跨卡 HCCS 静态拓扑和链路状态；当前主机内全部可见 A3 卡和 die；不包含：动态数据正确性、跨主机通信、L1 1520 灵衢 CC 版本 | A3 节点内 die 间基础互联不可用。 | 遍历全部可见 A3 card/die，检查 SIO/HCCS 拓扑、health、lane 完整性和链路速率 | `hccs_static` `{"coverage":"all_visible_cards_and_dies","same_card_relation":"SIO","cross_card_relations":["HCCS","HCCS_SW"],"required_health":"OK","require_complete_lanes":true,"require_positive_speed":true}` | 根据失败 card/die 和 lane 检查对应 SIO/HCCS 物理链路，修复后复测。 | 是 | A3 | memcache,mooncake | hccs | all | docker | 已实现 |
| HCCS-002 | A3 节点内卡间动态通信异常 | A3 NPU 节点内互联；全部可见 die 间 HCCL 动态数据通路；当前主机内全部可见 A3 die；不包含：跨主机通信、固定带宽门限、历史累计错误计数 | A3 节点内 HCCL 数据交换不可靠。 | 静态链路正常且全部 NPU 空闲时，为每个可见 die 启动一个 HCCL rank，执行 all-to-all 数据正确性测试并比较本次 HCCS retry/error 增量 | `hccs_dynamic` `{"collective":"all_to_all_single","coverage":"all_visible_dies","elements_per_peer":16384,"iterations":3,"timeout_seconds":90,"counter_mode":"delta","required_retry_error_delta":0}` | 根据失败 rank 或新增 retry/error 计数定位 HCCL 数据通路，修复后复测。 | 是 | A3 | memcache,mooncake | hccs | all | docker | 已实现 |
| ROCE-001 | NPU RoCE 端口未就绪 | NPU 设备侧；逐 NPU 端口静态就绪状态；当前主机内全部可见 NPU；不包含：本机卡间数据通路、跨主机网络连通性 | 对应 NPU RoCE 端口不可用。 | 逐卡使用 hccn_tool 读取 IP、掩码、Link、net health 和 MTU，检查 IP 唯一及掩码、MTU 一致性；不发送测试流量 | `roce_link` `{"coverage":"all_visible_npus","required_link":"UP","required_health":"Success","require_unique_ip":true,"require_consistent_netmask_mtu":true}` | 根据失败 NPU 检查 IP、掩码、Link、net health 和 MTU，修复端口静态状态后复测。 | 是 | A2,A3 | memcache,mooncake | roce | all | docker | 已实现 |
| ROCE-002 | NPU RoCE 本机卡间数据通路异常 | NPU 设备侧；本机 NPU 卡间动态数据通路；当前主机内全部 N*(N-1) 有向卡对；不包含：跨主机网络连通性 | 本机 NPU 间 RoCE 数据传输不可靠。 | 端口静态状态正常时，对全部可见 NPU 执行 N*(N-1) 个有向 hccn_tool ping，检查丢包和本次 FCS、RoCE、校验和及 QP 错误计数增量 | `roce_local` `{"coverage":"all_directed_pairs","packet_size":"minimum_mtu_minus_32","required_packet_loss_percent":0,"error_counter_mode":"delta","timeout_seconds":15}` | 根据失败有向卡对或新增错误计数检查源/目标 NPU、交换机端口、VLAN/PFC 和 HCCN 配置，修复后复测本机全矩阵。 | 是 | A2,A3 | memcache,mooncake | roce | all | docker | 已实现 |
| DOCKER-001 | Docker 未透传 Ascend 设备、驱动或 HCCN 入口 | - | 容器无法访问 NPU、驱动或可用的 HCCN 入口，kvpool 无法正常初始化。 | 检查 Docker 标识、npu-smi、/dev/davinci*、/usr/local/Ascend/driver，并确认 /etc/hccn.conf 或可执行 hccn_tool 至少存在一个 | `docker_prereqs` `{"required_all":["docker","npu_smi","davinci_device_count","driver_dir"],"required_any":[["hccn_conf","hccn_tool"]]}` | 重新创建容器，透传 Ascend 设备和驱动目录，并挂载 /etc/hccn.conf 或确保 hccn_tool 可执行，然后复测。 | 是 | A2,A3 | memcache,mooncake | all | all | docker | 已实现 |
| DEP-MOONCAKE-001 | mooncake-transfer-engine-npu 未安装或版本低于 0.3.11.post1 | - | Mooncake 后端软件依赖不满足，kvpool 无法可靠运行。 | 通过 Python 包元数据读取 mooncake-transfer-engine-npu 版本 | `package_version` `{"package":"mooncake-transfer-engine-npu","threshold":"0.3.11.post1"}` | 将 mooncake-transfer-engine-npu >=0.3.11.post1 的离线 wheel 固化到镜像，重建容器后复测。 | 是 | A2,A3 | mooncake | all | all | docker | 已实现 |
| DEP-MOONCAKE-002 | glibc 版本低于 2.35 | - | Mooncake wheel 运行时依赖不满足，后端无法正常加载。 | 解析容器内 ldd --version 的 glibc 版本 | `version_range` `{"operator":"lt","threshold":"2.35.0","unknown_status":"BLOCK"}` | 选择 glibc >=2.35 的基础镜像重新构建运行镜像，然后复测。 | 是 | A2,A3 | mooncake | all | all | docker | 已实现 |
| DEP-MEMCACHE-001 | memfabric-hybrid 未安装 | - | Memcache 后端缺少必需依赖，kvpool 无法正常运行。 | 通过 Python 包元数据确认 memfabric-hybrid 已安装 | `package_version` `{"package":"memfabric-hybrid"}` | 将 memfabric-hybrid 离线安装包固化到镜像，重建容器后复测。 | 是 | A2,A3 | memcache | all | all | docker | 已实现 |
| DEP-MEMCACHE-002 | memcache-hybrid 未安装 | - | Memcache 后端缺少必需依赖，kvpool 无法正常运行。 | 通过 Python 包元数据确认 memcache-hybrid 已安装 | `package_version` `{"package":"memcache-hybrid"}` | 将 memcache-hybrid 离线安装包固化到镜像，重建容器后复测。 | 是 | A2,A3 | memcache | all | all | docker | 已实现 |
| DEP-MEMCACHE-SSD-001 | memcache-hybrid 未安装或版本低于 1.2.0 | - | SSD Cache 依赖不满足，Memcache SSD Offload 无法正常工作。 | 通过 Python 包元数据读取 memcache-hybrid 版本 | `package_version` `{"package":"memcache-hybrid","threshold":"1.2.0"}` | 将 memcache-hybrid 升级到 >=1.2.0 并固化到镜像，重建容器后复测。 | 是 | A2,A3 | memcache | all | all | docker | 已实现 |
| SSD-001 | SSD Offload 存储条件不满足 | - | SSD Offload 无法初始化。 | 按照当前后端的存储策略检查 --ssd-path | `ssd_storage` `{"path_required":true}` | 按照检测详情准备当前后端所需的 SSD 路径后复测。 | 是 | A2,A3 | memcache,mooncake | all | all | docker | 已实现 |

<!-- END GENERATED RULE PANORAMA -->
