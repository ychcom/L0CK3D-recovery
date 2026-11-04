# 工具集说明

> 这些脚本是**四天实战中边打边写**的产物，不是通用产品。
> 它们假设：源盘已只读挂载、Alpine/任意 Linux + `btrfs-progs` + Python3、extent/inode 表已导出。
> 仓库内所有通道地址已替换为占位符，使用前请替换为你的实际地址。

## 快速上手顺序

```
1. dump_ext.py   → 导出 extent 表（全局只做一次）
2. inomap.py     → 导出 inode→路径/大小 表
3. footer_scan.py→ 批量判定 mode（决定哪些文件值得动手）★先跑这个
4. cov.py        → 旧 extent 覆盖率普查（判断批量投入是否划算）
5. restore.py    → CoW 反演主程序
6. rebuild.py    → 对"部分损坏"文件做多版本拼接增强
7. upload2.py    → 产物回传（通道环境用）
```

**不要跳过第 3 步。** 先知道哪些是 `0x24`（全加密、终局不可恢复），能省下大量无效算力。

---

## 脚本清单

### `dump_ext.py <subvol_id> <out.tsv>`
导出指定子卷的 extent 表。输出列含：inode、文件偏移、**extent 逻辑地址**、generation、extent 总大小等。

> ⚠️ 逻辑地址**不是物理地址**，必须经 chunk 表做 l2p（logical→physical）换算后才能 seek 读取。直接当物理地址用会读到乱码——这是本项目最早踩的坑。

### `inomap.py <subvol_id> <out.tsv>`
导出 inode → 路径 / 大小 映射，用于把 inode 号还原成人类可读路径。

### `footer_probe.py <inode[,inode...]> [labfile]`
解析单个/若干文件的勒索尾记录（588B），输出：

- `mode`：`0x24` 全加密 / `0x25` 分段 / `0x26` 仅前 1MiB
- `crypto`：`0x20` 真加密 / `0x21` 诱饵
- 原始文件大小（尾记录偏移 580，8 字节）
- 攻击 marker（同一次攻击的全盘文件应一致）

默认读取 `EXT = /root/ext<sid>.tsv`，按你的子卷改。

### `footer_scan.py <list.tsv>`
批量版。输入格式 `inode \t 当前大小 \t 路径`，逐行解析并汇总 mode 分布。
**用途**：在动手前完成可恢复性分流。

### `cov.py`
旧 extent 覆盖率普查：统计每个目标文件有多少字节能被 `gen < NEWGEN` 的旧 extent 覆盖。
**用途**：判断某批文件是否值得跑全量反演。覆盖率 0 = 别浪费时间。

### `restore.py <subvol_id> <list.tsv> <outdir> [upload_url]`
CoW 反演主程序。输入清单格式：

```
name \t inode \t 当前大小 \t 原始大小 \t 相对路径
```

输出还原文件 + `manifest.tsv`（含 SHA256、密文段统计、容器魔数与结构自检结果）。
关键环境量：`EXTFILE`（extent 表路径）、`NEWGEN=4450000`（攻击代，按你的实际盘调整）。

> 注意：对 16KB 以下小文件，`conf=NO_CIPHER` 可能是熵判据失效导致的**误判**，务必用魔数复核（例如 RAR 应以 `Rar!` 开头）。

### `rebuild.py <inode[,inode...]>`
extent 拼接增强：除常规旧 extent 外，额外利用旧 extent 的**剩余空间**残留（extent 总大小 > 文件占用时的尾部），做多版本择优拼接。
本项目用此将一张 JPEG 修复至 100% 无损；但对另外 10 张同类照片全部无效。**先跑 `cov.py` 再决定**。

### `carve_hua.py <start> <end> <outdir>`
魔数雕刻（按字节区间扫描并切出 JPEG/PDF/ZIP 等）。
**本项目结论：对 0x24 全加密文件无效**，保留在此仅作方法学记录与否定证据。

### `read_gap.py <logical> <want_start> <want_len>`
直接读取指定 extent 内的偏移区间，用于人工核查某个"空洞"到底有没有原文残留。
注意不要越过尾记录里的原始大小边界，否则会读到尾记录本身。

### `upload2.py <file> <url>`
把产物回传到分析机。本项目通道环境为跳板机 + 串口 + 单向 HTTP，故单独成脚本；普通环境可直接 scp。

---

## 使用前提与红线

1. **源盘零写入**：`losetup -r`，禁用 `balance / defrag / discard / repair / rw mount`。动手前先取 SHA 基线。
2. **先取样再全量**：本项目用 32 个样本端到端验证方法论后才铺开。
3. **产物三副本**：工作目录 → 异地备份 → 过程产物归档。中间产物不轻删（本项目曾两次因批量清理脚本误删完好文件）。
4. **VM 无持久化**：若用临时 VM 做计算，中间表与产物必须及时回传，否则 VM 一崩全丢（本项目实际发生过一次）。

## 已知局限

- `NEWGEN` 与子卷 ID 是**本案例硬编码值**，换盘必须重新判定。
- 工具面向 btrfs；ext4/xfs/NTFS 无 CoW 保证，主路线不适用。
- 对 `0x24` 全加密文件，本套工具**只能给出不可恢复的判定**，无法解密。
