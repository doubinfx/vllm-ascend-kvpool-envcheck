# vLLM-Ascend kvpool 环境检测工具 v14.1.1

该工具用于 vLLM-Ascend kvpool 部署前环境检查：识别依赖问题、输出阻塞项和修复建议，并在显式授权后执行当前支持的本地修复。

工具只支持在 vLLM-Ascend Docker 容器内运行，运行时不联网，默认只读。规则和支持范围以同目录下的 `rules.json` 为准；实现和判定细节见 [DESIGN.md](DESIGN.md)。

## 快速开始

### 只回显检查报告

```bash
python3 kvpool_envcheck.py \
  --hardware A3 \
  --backend memcache \
  --managed-memory-mb 32768 \
  --deployment-mode single-node \
  --link-type hccs
```

该模式不创建文件，检查报告直接输出到标准输出，运行进度输出到标准错误。

### 保存检测结果

```bash
python3 kvpool_envcheck.py \
  --hardware A3 \
  --backend memcache \
  --managed-memory-mb 32768 \
  --deployment-mode multi-node \
  --link-type hccs \
  --output-dir ./results
```

一次检测生成一对使用同一 `run_id` 的文件：

| 文件 | 用途 |
|---|---|
| `kvpool_envcheck_<run_id>.result.json` | 完整机器可读结果、原始证据、修复动作和参考文档 |
| `kvpool_envcheck_<run_id>.report.txt` | 面向使用者的环境检测报告，突出结论、阻塞项和建议 |

未指定 `--output-dir` 时不创建文件；指定目录时，标准输出只回显最终结论、`run_id` 和文件路径。

## 参数和组合限制

运行 `python3 kvpool_envcheck.py -h` 查看当前规则目录动态生成的完整帮助。检测模式必须同时提供以下参数：

| 参数 | 说明 |
|---|---|
| `--hardware` | 硬件平台。当前支持 A2、A3，且必须与当前容器识别到的硬件一致 |
| `--backend` | KV Pool 后端。当前支持 `memcache`、`mooncake` |
| `--managed-memory-mb MB` | 后端纳管内存总量，单位 MB，必须大于 0；按全局容量比较 |
| `--deployment-mode` | `single-node` 或 `multi-node` |
| `--link-type` | `roce` 或 `hccs`；A2 只能使用 `roce`，A3 两者均可使用 |

组合约束：

- A2：只支持 RoCE 检查；
- A3 + `roce`：执行 RoCE 端口静态和本机卡间动态检查；
- A3 + `hccs`：执行节点内 SIO/HCCS 静态和动态检查；多节点时增加灵衢 CC 人工确认；
- `KERNEL-001` 只影响多节点部署，单节点返回 `NOT_APPLICABLE`，不阻塞部署；
- `--hardware` 不仅要在支持范围内，还必须与当前环境识别结果完全一致。

## SSD Offload

启用 SSD 检查时必须同时提供 `--ssd-path`：

```bash
python3 kvpool_envcheck.py \
  --hardware A3 \
  --backend memcache \
  --managed-memory-mb 32768 \
  --deployment-mode multi-node \
  --link-type hccs \
  --ssd-offload \
  --ssd-path /dev/nvme1n1 \
  --output-dir ./results
```

- `memcache`：`--ssd-path` 必须是未挂载、无文件系统签名的专用块设备、分区或 loop 设备，不能传目录；
- `mooncake`：可以传入可写且有可用空间的目录或块设备；
- 未启用 `--ssd-offload` 时，SSD 依赖场景不参与本次检测。

## 修复授权

`--fix` 表示明确授权工具执行当前已实现的本地修复：

```bash
python3 kvpool_envcheck.py \
  --hardware A3 \
  --backend memcache \
  --managed-memory-mb 32768 \
  --deployment-mode multi-node \
  --link-type hccs \
  --fix \
  --output-dir ./results
```

当前只有 A3 的 `MEM-001` 支持自动修复：1GB、2MB 扫描均显示全局容量不足时，工具在容器内尝试 Drop Cache 并复测。该动作要求容器内 root 权限和可写的 `/proc/sys/vm/drop_caches`，可能短时影响 I/O。

A2 静态大页不足不执行 Drop Cache。HDK、CANN、kernel、网络设备、容器挂载和软件包升级等动作不会自动执行，结果中会给出人工处理建议。修复动作状态包括 `SUCCESS`、`NO_EFFECT`、`FAILED`、`SKIPPED` 和 `MANUAL`。

## 输出状态和退出码

单个问题场景可能返回：

- `PASS`：未发现该问题；
- `BLOCK`：发现阻塞问题；
- `WARN`：发现风险，需要确认；
- `MANUAL_REQUIRED`：需要人工确认；
- `NOT_APPLICABLE`：当前硬件、后端或部署模式不适用；
- `NOT_EXECUTED`：因前置条件不足未执行。

进程退出码：

| 退出码 | 含义 |
|---:|---|
| `0` | 检查通过 |
| `10` | 存在警告或需要人工确认 |
| `20` | 存在阻塞项 |
| `2` | 输入、规则或输出错误 |

实时进度默认使用 `--progress auto`：交互式终端显示，非交互调用自动关闭。也可以显式指定：

```bash
--progress always   # 始终显示
--progress never    # 关闭进度
```

进度只写入标准错误，不混入 TEXT/JSON 结果。每个实际检测阶段只输出开始、结束和耗时。

## 规则维护

`rules.json` 是问题场景、适用范围、判定方式和修复建议的唯一运行时事实源。规则支持范围会自动反映到 `-h` 帮助中，README 不重复维护规则清单。

```bash
# 校验规则目录
python3 kvpool_envcheck.py --validate-catalog

# 查看全部问题场景
python3 kvpool_envcheck.py --list-rules

# 查看单个问题场景
python3 kvpool_envcheck.py --describe-rule MEM-001

# 规则修改并校验通过后，同步设计文档中的规则全景
python3 kvpool_envcheck.py --sync-panorama DESIGN.md
```

`--sync-panorama` 只修改 `DESIGN.md` 的自动生成区域，不执行环境检测。

## 参考资料

工具结果中的 `reference_documents` 固化了官方 [vLLM-Ascend KV Cache Pool 用户手册](https://github.com/vllm-project/vllm-ascend/blob/main/docs/source/user_guide/feature_guide/kv_cache_pool_ascend_store.md) 的链接、版本和内容校验信息。工具运行时不联网。
