# v6 离线检测脚本

- `mem_scan.py`：A3 使用的官方用户指导文档原始文件，内容禁止修改；来源和提交号见 `manifest.json`；
- `hccs_test_a3.py`：A3 节点内 HCCL all-to-all 数据正确性测试；每个可见 die 启动一个 rank，仅使用本机回环地址完成通信域初始化，不访问外部网络；
- `manifest.json`：记录来源、提交号和 SHA256。

工具运行时不联网。更新A3官方脚本时必须重新固化原文件、更新提交号和校验值，并重新验证扫描结果。A3检测工具先执行1GB粒度扫描，全局可用容量不足时再执行2MB粒度扫描；A2读取`/proc/meminfo`静态2MB大页；纳管内存总量由`--managed-memory-mb`提供，不改写扫描脚本的`-m/--min-mb`语义。

HCCS 动态测试仅在 `HCCS-001` 通过且未发现 NPU 业务进程时执行。脚本依赖 vLLM-Ascend 运行镜像已有的 `torch`、`torch_npu` 和 HCCL，不在运行时安装依赖或编译二进制。
