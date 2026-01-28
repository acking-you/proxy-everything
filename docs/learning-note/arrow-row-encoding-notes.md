# DataFusion 排序 Row 编码探索笔记

> 本文基于本地源码阅读与手算推导，主要对应当前工作区里的 DataFusion 与 Arrow 版本。示例编码来自本机 `arrow-row-56.2.0` 代码实现，若版本变化编码细节可能略有差异。

## 背景

我在阅读 DataFusion 的排序优化时，看到 `datafusion/physical-plan/src/sorts/stream.rs` 中的 `convert_batch` 把多列排序键转换成 `arrow::row::Rows`。这让我产生了疑问：

- 为什么要把多列转换为“行格式”的 bytes？
- 直接用 bytes 比较怎么保证排序顺序正确？
- 既然最终排序还是按字段优先级，那这样做到底比逐列比较有什么优势？

带着这些问题，我继续追踪源码：从 DataFusion 的 `RowCursorStream` 一路进入 Arrow 的 `arrow-row`，最终确认 **RowConverter 生成的是“保序编码”的行字节**，它保证了字节序比较等价于多列排序比较，从而将多列比较简化为一次 memcmp。本文记录关键发现与具体示例。

## DataFusion 中的入口：`convert_batch`

关键逻辑在：

- `datafusion/physical-plan/src/sorts/stream.rs`

```
fn convert_batch(&mut self, batch: &RecordBatch, stream_idx: usize) -> Result<RowValues> {
    let cols = self
        .column_expressions
        .iter()
        .map(|expr| expr.evaluate(batch)?.into_array(batch.num_rows()))
        .collect::<Result<Vec<_>>>()?;

    let mut rows = self.rows.take_next(stream_idx)?;
    rows.clear();
    self.converter.append(&mut rows, &cols)?;

    let rows = Arc::new(rows);
    self.rows.save(stream_idx, Arc::clone(&rows));
    Ok(RowValues::new(rows, rows_reservation))
}
```

这里的核心是：**把排序列数组交给 `RowConverter`，产出 `Rows`（行格式 bytes）**。

后续排序比较发生在：

- `datafusion/physical-plan/src/sorts/cursor.rs`

```
impl CursorValues for RowValues {
    fn compare(l: &Self, l_idx: usize, r: &Self, r_idx: usize) -> Ordering {
        l.rows.row(l_idx).cmp(&r.rows.row(r_idx))
    }
}
```

`Row::cmp` 只是对 `&[u8]` 做字节序比较。这意味着 **“列排序顺序”已经被编码进 bytes**。

## Arrow RowConverter：保序编码的核心

RowConverter 位于 `arrow-row` crate：

- `~/.cargo/registry/src/.../arrow-row-56.2.0/src/lib.rs`

它的文档明确说明：Row 格式经过 **排序归一化**，保证字节序比较等价于多列 lexicographic 排序。

### 编码总原则

每一列会先被编码成一个“保序字节序列”，然后按 sort key 顺序串联成整行。这样整行 bytes 的字典序比较，就等价于逐列比较。

### 关键点一：固定长度类型

统一格式：

```
[validity(1 byte)] [encoded bytes...]
```

- valid=0x01 表示非 NULL
- NULL sentinel：nulls_first 用 0x00；nulls_last 用 0xFF

#### 有符号整数（i8/i16/i32…）

- 大端序
- 翻转最高位（符号位）

**为什么翻转符号位能保序？**

原始补码表示（以 i8 为例）：

```
值      二进制        十六进制
-128    1000 0000     0x80
-1      1111 1111     0xFF
 0      0000 0000     0x00
 1      0000 0001     0x01
 127    0111 1111     0x7F
```

问题：负数的最高位是 1，正数是 0。按无符号字节序比较会得到错误结果：

```
-128 (0x80) > 127 (0x7F)  ❌ 错误！
```

翻转符号位后：

```
值      原始          翻转后
-128    1000 0000     0000 0000  (0x00)
-1      1111 1111     0111 1111  (0x7F)
 0      0000 0000     1000 0000  (0x80)
 1      0000 0001     1000 0001  (0x81)
 127    0111 1111     1111 1111  (0xFF)
```

现在字节序比较正确：

```
-128 (0x00) < -1 (0x7F) < 0 (0x80) < 1 (0x81) < 127 (0xFF)  ✓
```

**示例：i32 = -5**

- 原始大端：`FF FF FF FB`
- 翻符号位：`7F FF FF FB`
- 加有效位：`01 7F FF FF FB`

**更多示例：**

```
i32 = -2147483648 (MIN)  →  01 00 00 00 00
i32 = -1                 →  01 7F FF FF FF
i32 = 0                  →  01 80 00 00 00
i32 = 1                  →  01 80 00 00 01
i32 = 2147483647 (MAX)   →  01 FF FF FF FF
```

#### 无符号整数（u16/u32…）

直接大端序

示例：u16 = 258 (0x0102)

```
01 01 02
```

#### 浮点数（f32/f64）

- 先执行 IEEE754 total order 的变换
- 再按有符号整数编码

**IEEE754 浮点数的位模式问题：**

浮点数的原始位模式不能直接用于字节序比较：

1. **正数**：符号位 0，指数和尾数按大小排列 → 字节序正确
2. **负数**：符号位 1，但 -1.0 的位模式 > -2.0 的位模式 → 错误！
3. **特殊值**：NaN、±Inf、±0 需要特殊处理

**Total Order 变换规则：**

```
如果符号位 = 0（正数/+0/+Inf/部分NaN）：翻转符号位
如果符号位 = 1（负数/-0/-Inf/部分NaN）：翻转所有位
```

**示例 f32 编码过程：**

```
值       IEEE754原始      变换规则      变换后          最终编码(含validity)
-2.0     C0 00 00 00      翻转全部      3F FF FF FF     01 3F FF FF FF
-1.0     BF 80 00 00      翻转全部      40 7F FF FF     01 40 7F FF FF
-0.0     80 00 00 00      翻转全部      7F FF FF FF     01 7F FF FF FF
+0.0     00 00 00 00      翻转符号      80 00 00 00     01 80 00 00 00
+1.0     3F 80 00 00      翻转符号      BF 80 00 00     01 BF 80 00 00
+1.5     3F C0 00 00      翻转符号      BF C0 00 00     01 BF C0 00 00
+2.0     40 00 00 00      翻转符号      C0 00 00 00     01 C0 00 00 00
+Inf     7F 80 00 00      翻转符号      FF 80 00 00     01 FF 80 00 00
```

**验证排序正确性：**

```
3F FF FF FF < 40 7F FF FF < 7F FF FF FF < 80 00 00 00 < BF 80 00 00 < C0 00 00 00
    -2.0    <    -1.0     <    -0.0     <    +0.0     <    +1.0     <    +2.0     ✓
```

示例：f32 = 1.5

```
01 BF C0 00 00
```

#### bool

```
01 01  // true
01 00  // false
```

#### FixedSizeBinary(n)

```
01 [n bytes]
```

NULL -> `00` + n 个 0

### 关键点二：变长类型（Utf8 / Binary）

编码规则：

```
NULL     -> [00]
EMPTY    -> [01]
NONEMPTY -> [02] + blocks...
```

**Block 编码规则详解：**

- 每个 block 固定 9 字节：8 字节数据槽 + 1 字节标记
- 数据槽不足 8 字节时用 0x00 填充
- 标记字节含义：
  - `0xFF` = 还有后续 block
  - `1~8` = 最后一个 block，值为有效字节数

**多长度示例：**

```
"" (空字符串):
  01
  ^
  空sentinel

"a" (1字节):
  02 61 00 00 00 00 00 00 00 01
  ^  ^----------------------- ^
  |  数据槽(8字节,填充0)      长度=1
  非空sentinel

"ab" (2字节):
  02 61 62 00 00 00 00 00 00 02
  ^  ^--^------------------- ^
  |  数据                    长度=2
  非空sentinel

"abcdefg" (7字节):
  02 61 62 63 64 65 66 67 00 07
  ^  ^------------------^--- ^
  |  7字节数据           填充 长度=7
  非空sentinel

"abcdefgh" (8字节，刚好填满一个block):
  02 61 62 63 64 65 66 67 68 08
  ^  ^---------------------- ^
  |  8字节数据               长度=8
  非空sentinel

"abcdefghi" (9字节，需要两个block):
  02 61 62 63 64 65 66 67 68 FF 69 00 00 00 00 00 00 00 01
  ^  ^---------------------- ^  ^---------------------- ^
  |  第1个block(8字节)       |  第2个block(1字节+填充)  长度=1
  非空sentinel               继续标记

"123456789012345678" (18字节，需要三个block):
  02 31 32 33 34 35 36 37 38 FF 39 30 31 32 33 34 35 36 FF 37 38 00 00 00 00 00 00 02
  ^  ^-- block 1 (8字节) --^ ^  ^-- block 2 (8字节) --^ ^  ^-- block 3 (2字节) --^ ^
  |                          |                          |                          长度=2
  非空sentinel               继续                       继续
```

**为什么这样设计？**

一个自然的疑问是：为什么不能直接把字符串的原始字节拼接在一起？

**问题一：多列边界丢失**

```
Row1: country="CN",  city="Beijing"  → 43 4E 42 65 69 6A 69 6E 67
Row2: country="CNB", city="eijing"   → 43 4E 42 65 69 6A 69 6E 67  (相同！)
```

**问题二：前缀歧义**

```
Row1: country="US",  city="A"   → 55 53 41
Row2: country="USA", city=""    → 55 53 41  (相同！)
```

**问题三：NULL 无法表示**

直接拼接无法区分 NULL 和空字符串。

**问题四：长度不同时的比较**

`"ab"` 和 `"abc"` 前缀相同，但我们期望 `"ab" < "abc"`。

**解决方案总结：**

| 问题 | arrow-row 的解决方案 |
|------|---------------------|
| 列边界丢失 | 固定宽度 block，每列有明确边界 |
| 前缀歧义 | 填充 0x00 + 长度标记 |
| NULL 无法表示 | Sentinel：00=NULL, 01=空, 02=非空 |
| 长度不同 | 0x00 填充保证短串 < 长串前缀 |

**设计哲学**：牺牲少量空间（sentinel + 填充），换取 memcmp 的正确性和高效性。

### 关键点三：Struct

```
NULL -> [00]
非空 -> [01] + 子字段编码（按字段顺序）
```

### 关键点四：List

List 的编码最关键：

1) 子元素先各自编码成 "row bytes"
2) 每个子元素 row bytes 再用"变长编码"包一层
3) 串联所有元素
4) 末尾追加一个 empty sentinel（`01`）

这保证了 list 的字节序比较等价于逐元素比较。

**List<i8> 编码详细过程：**

原始数据: `[1, NULL, 2]`

```
Step 1: 每个元素先编码为 row bytes
        ┌─────────────────────────────────────────┐
        │ 元素 1:    01 81                        │  validity=01, 值=1 翻转符号位=81
        │ 元素 NULL: 00                           │  NULL sentinel
        │ 元素 2:    01 82                        │  validity=01, 值=2 翻转符号位=82
        └─────────────────────────────────────────┘

Step 2: 每个元素的 row bytes 用变长编码包装
        ┌─────────────────────────────────────────┐
        │ 元素 1:    02 01 81 00 00 00 00 00 00 02│  非空(02) + 数据 + 长度=2
        │ 元素 NULL: 02 00 00 00 00 00 00 00 00 01│  非空(02) + 数据 + 长度=1
        │ 元素 2:    02 01 82 00 00 00 00 00 00 02│  非空(02) + 数据 + 长度=2
        └─────────────────────────────────────────┘

Step 3: 串联所有元素 + 末尾 empty sentinel
        02 01 81 00 00 00 00 00 00 02  ← 元素 1
        02 00 00 00 00 00 00 00 00 01  ← 元素 NULL
        02 01 82 00 00 00 00 00 00 02  ← 元素 2
        01                             ← 结束标记(empty sentinel)
```

**为什么末尾需要 empty sentinel？**

考虑比较 `[1]` 和 `[1, 2]`：

```
[1]:    02 01 81 00 00 00 00 00 00 02 | 01
[1, 2]: 02 01 81 00 00 00 00 00 00 02 | 02 01 82 ...
                                       ^
                                       01 < 02，所以 [1] < [1, 2]  ✓
```

如果没有 empty sentinel，`[1]` 的编码会是 `[1, 2]` 的前缀，无法正确比较。

### 降序 / nulls_last

- nulls_last：NULL sentinel 改为 0xFF
- descending：
  - 固定长度类型：**只翻转值字节**
  - 变长类型：**翻转整个编码**

这样 memcmp 仍然可直接用来比较降序。

## 实战示例：多字符串列排序

为了更直观地理解 row 编码在实际排序中的作用，我们用一个纯字符串多列排序的例子来演示完整流程。

### 场景：用户表按 (country, city, name) 排序

```sql
SELECT * FROM users ORDER BY country ASC, city ASC, name ASC;
```

### 原始数据

| row | country | city     | name    |
|-----|---------|----------|---------|
| R1  | "CN"    | "Beijing"| "Alice" |
| R2  | "CN"    | "Beijing"| "Bob"   |
| R3  | "CN"    | "Shanghai"| "Carol"|
| R4  | "US"    | "NYC"    | "David" |
| R5  | NULL    | "Tokyo"  | "Eve"   |

### Step 1: 逐列编码

每个字符串按变长编码规则转换：

**country 列编码：**

```
R1 "CN":    02 43 4E 00 00 00 00 00 00 02
               C  N  ←填充→        长度=2

R2 "CN":    02 43 4E 00 00 00 00 00 00 02

R3 "CN":    02 43 4E 00 00 00 00 00 00 02

R4 "US":    02 55 53 00 00 00 00 00 00 02
               U  S  ←填充→        长度=2

R5 NULL:    00
            ↑ NULL sentinel (nulls_first)
```

**city 列编码：**

```
R1 "Beijing":  02 42 65 69 6A 69 6E 67 00 07
                  B  e  i  j  i  n  g     长度=7

R2 "Beijing":  02 42 65 69 6A 69 6E 67 00 07

R3 "Shanghai": 02 53 68 61 6E 67 68 61 69 FF 00 00 00 00 00 00 00 00 01
                  S  h  a  n  g  h  a  i  ↑  ←第2个block→     长度=1
                                         继续标记

R4 "NYC":      02 4E 59 43 00 00 00 00 00 03
                  N  Y  C  ←填充→        长度=3

R5 "Tokyo":    02 54 6F 6B 79 6F 00 00 00 05
                  T  o  k  y  o           长度=5
```

**name 列编码：**

```
R1 "Alice":  02 41 6C 69 63 65 00 00 00 05
                A  l  i  c  e           长度=5

R2 "Bob":    02 42 6F 62 00 00 00 00 00 03
                B  o  b  ←填充→        长度=3

R3 "Carol":  02 43 61 72 6F 6C 00 00 00 05
                C  a  r  o  l           长度=5

R4 "David":  02 44 61 76 69 64 00 00 00 05
                D  a  v  i  d           长度=5

R5 "Eve":    02 45 76 65 00 00 00 00 00 03
                E  v  e  ←填充→        长度=3
```

### Step 2: 串联成完整 Row

每行的编码 = country 编码 + city 编码 + name 编码

```
R1: 02 43 4E 00 00 00 00 00 00 02 | 02 42 65 69 6A 69 6E 67 00 07 | 02 41 6C 69 63 65 00 00 00 05
    |-------- country --------| |---------- city ----------| |---------- name ----------|

R2: 02 43 4E 00 00 00 00 00 00 02 | 02 42 65 69 6A 69 6E 67 00 07 | 02 42 6F 62 00 00 00 00 00 03
    |-------- country --------| |---------- city ----------| |---------- name ----------|

R3: 02 43 4E 00 00 00 00 00 00 02 | 02 53 68 61 6E 67 68 61 69 FF 00 00 00 00 00 00 00 00 01 | 02 43 61 72 6F 6C 00 00 00 05
    |-------- country --------| |------------------- city (2 blocks) -------------------| |---------- name ----------|

R4: 02 55 53 00 00 00 00 00 00 02 | 02 4E 59 43 00 00 00 00 00 03 | 02 44 61 76 69 64 00 00 00 05
    |-------- country --------| |---------- city ----------| |---------- name ----------|

R5: 00 | 02 54 6F 6B 79 6F 00 00 00 05 | 02 45 76 65 00 00 00 00 00 03
    |N| |---------- city ----------| |---------- name ----------|
```

### Step 3: memcmp 排序

现在只需对这些字节序列做字典序排序：

```
排序前（按原始行号）：
R1: 02 43 4E 00 00 00 00 00 00 02 02 42 65 69 6A 69 6E 67 00 07 02 41 6C ...
R2: 02 43 4E 00 00 00 00 00 00 02 02 42 65 69 6A 69 6E 67 00 07 02 42 6F ...
R3: 02 43 4E 00 00 00 00 00 00 02 02 53 68 61 6E 67 68 61 69 FF ...
R4: 02 55 53 00 00 00 00 00 00 02 02 4E 59 43 ...
R5: 00 02 54 6F 6B 79 6F ...

排序后：
R5: 00 ...                          ← NULL 最小 (0x00)
R1: 02 43 4E ... 02 42 65 ... 02 41 ← CN + Beijing + Alice
R2: 02 43 4E ... 02 42 65 ... 02 42 ← CN + Beijing + Bob (Alice < Bob)
R3: 02 43 4E ... 02 53 68 ...       ← CN + Shanghai (Beijing < Shanghai)
R4: 02 55 53 ...                    ← US (CN < US)
```

### Step 4: 比较过程详解

**比较 R1 vs R2：**

```
偏移:  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 ...
R1:   02 43 4E 00 00 00 00 00 00 02 02 42 65 69 6A 69 6E 67 00 07 02 41 6C ...
R2:   02 43 4E 00 00 00 00 00 00 02 02 42 65 69 6A 69 6E 67 00 07 02 42 6F ...
      =  =  =  =  =  =  =  =  =  =  =  =  =  =  =  =  =  =  =  =  =  <
      |-------- country --------| |---------- city ----------| |-- name --|
                                                                   ↑
                                                            偏移21: 41 < 42
                                                            'A' < 'B'
结论: R1 < R2
```

**比较 R1 vs R3：**

```
偏移:  0  1  2  3  4  5  6  7  8  9 10 11 12 13 ...
R1:   02 43 4E 00 00 00 00 00 00 02 02 42 65 69 ...
R3:   02 43 4E 00 00 00 00 00 00 02 02 53 68 61 ...
      =  =  =  =  =  =  =  =  =  =  =  <
      |-------- country --------| |-- city --|
                                     ↑
                              偏移11: 42 < 53
                              'B' < 'S' (Beijing < Shanghai)
结论: R1 < R3
```

**比较 R1 vs R4：**

```
偏移:  0  1  2  3 ...
R1:   02 43 4E 00 ...
R4:   02 55 53 00 ...
      =  <
      |country|
         ↑
   偏移1: 43 < 55
   'C' < 'U' (CN < US)
结论: R1 < R4
```

**比较 R5 vs R1：**

```
偏移:  0 ...
R5:   00 ...
R1:   02 ...
      <
      ↑
偏移0: 00 < 02
NULL sentinel < 非空 sentinel
结论: R5 < R1
```

### 最终排序结果

| 排序后 | country | city      | name    |
|--------|---------|-----------|---------|
| R5     | NULL    | "Tokyo"   | "Eve"   |
| R1     | "CN"    | "Beijing" | "Alice" |
| R2     | "CN"    | "Beijing" | "Bob"   |
| R3     | "CN"    | "Shanghai"| "Carol" |
| R4     | "US"    | "NYC"     | "David" |

### 关键观察

1. **NULL 自动排最前**：因为 NULL sentinel (0x00) < 非空 sentinel (0x02)
2. **字符串按字典序**：因为 UTF-8 编码本身就是字典序友好的
3. **多列优先级自动保证**：country 编码在前，所以先比较 country
4. **长度不同也能正确比较**：
   - "Beijing" (7字节) vs "Shanghai" (8字节，跨 block)
   - 填充的 0x00 保证短字符串 < 长字符串的相同前缀


## 综合示例：多类型排序键

展示包含所有类型的复杂排序键编码（全部升序 + nulls_first）：

```
Sort Key: i32, u16, f32, bool, utf8, binary, fixed_size_binary(3), struct<i16, utf8>, list<int8>
```

### Row A 数据与编码

```
数据                          编码
─────────────────────────────────────────────────────────────
i32=-5                        01 7F FF FF FB
u16=258                       01 01 02
f32=1.5                       01 BF C0 00 00
bool=true                     01 01
utf8="ab"                     02 61 62 00 00 00 00 00 00 02
binary=[01 FF]                02 01 FF 00 00 00 00 00 00 02
fsb(3)=[10 20 30]             01 10 20 30
struct={-2, "hi"}             01 01 7F FE 02 68 69 00 00 00 00 00 00 02
list=[1, NULL]                02 01 81 00 00 00 00 00 00 02
                              02 00 00 00 00 00 00 00 00 01
                              01
```

### Row B vs Row A（utf8 不同）

```
A utf8="ab": 02 61 62 ...  →  62 < 63  →  A < B
B utf8="ac": 02 61 63 ...
```

### Row C vs Row A（list 不同）

```
A list=[1, NULL]: ... 02 00 00 ...  →  00 < 01  →  A < C (NULL < 2)
C list=[1, 2]:    ... 02 01 82 ...
```

## 为什么这样更快

**memcmp 的工作原理：**
- 逐字节扫描，一旦发现不等字节立即返回
- 字段边界对 memcmp 透明，只看字节
- 编码保证字节序 = 语义序
- 差异越靠前，比较越快（早停优化）

**性能优势：**
1. 多列比较变为一次 memcmp
2. 避免在比较时多次访问列数组 + 分支判断
3. Row buffer 连续，缓存友好，适合向量化
4. 便于跨 batch/partition 直接比较

## 代价与权衡

- 需要额外编码成本
- 额外内存（Rows buffer）

因此 DataFusion 在单列 primitive 排序时会走 `FieldCursorStream` 的专门路径，避免 RowConverter 开销。

## Arrow C++ 与 Rust arrow-row 的区别

一个常见的疑问是：Arrow C++ 库中是否有类似的保序编码？

### 答案：不同的实现，不同的目标

Arrow C++ 在 `cpp/src/arrow/compute/row/` 目录下确实有 row 编码实现，但它的设计目标与 Rust 的 `arrow-row` **完全不同**：

| 特性 | Arrow C++ row | Rust arrow-row |
|------|---------------|----------------|
| **主要用途** | Hash table、groupby、join | 排序比较 |
| **编码目标** | 高效随机访问、哈希计算 | **保序编码**（memcmp = 语义比较） |
| **整数编码** | 直接存储（无符号位翻转） | 翻转符号位 |
| **浮点编码** | 直接存储 | IEEE754 total order 变换 |
| **字符串编码** | 长度 + 原始数据 | block 编码（填充 + 长度标记） |
| **NULL 处理** | 位掩码 | sentinel 字节（0x00/0xFF） |
| **比较方式** | 需逐字段解析比较 | 直接 memcmp |

### Arrow C++ row 格式的设计

Arrow C++ 的 row 格式（定义在 `row_internal.h`）主要特点：

```
内存布局：
┌──────────────┬─────────────────────────┬──────────────────┐
│  Null masks  │  Fixed-length data/     │  Variable-length │
│  (bit flags) │  offsets                │  data            │
└──────────────┴─────────────────────────┴──────────────────┘
```

- 使用位掩码表示 NULL
- 固定长度字段直接存储原始值
- 变长字段使用 32-bit offset 指向数据区
- 支持 power-of-2 对齐优化

这种格式适合：
- Hash join 中的 probe/build 操作
- Group by 的 key 匹配
- 需要随机访问行数据的场景

但**不适合**直接用于排序比较，因为：
- 有符号整数的字节序不等于数值序
- 浮点数的字节序不等于数值序
- 比较时需要解析每个字段

### 为什么 C++ 没有等价的保序编码？

Arrow C++ 的排序通常采用不同策略：

1. **索引排序（argsort）**：生成排序后的行索引，而非编码后比较
2. **Comparator 函数**：使用逐列比较的 comparator
3. **外部排序**：大规模数据使用分块排序 + 归并

Rust 的 `arrow-row` 是 DataFusion 项目驱动的优化，专门为多列排序场景设计。它的文档明确说明：

> *"The encoding of the row format may change from release to release."*

这意味着它是 Rust 实现的内部优化，而非跨语言标准。

### 类似实现

如果在 C++ 生态中需要类似的保序编码，可以参考：

- **DuckDB** 的 row 格式：也实现了类似的保序编码用于排序
- **ClickHouse** 的 key 编码：用于主键排序和索引
- 自行实现：按照本文描述的编码规则

### 参考链接

- [Arrow C++ compute/row 源码](https://github.com/apache/arrow/tree/main/cpp/src/arrow/compute/row)
- [Rust arrow-row 文档](https://arrow.apache.org/rust/arrow_row/struct.RowConverter.html)

## 参考源码位置（本地）

- DataFusion:
  - `datafusion/physical-plan/src/sorts/stream.rs`
  - `datafusion/physical-plan/src/sorts/cursor.rs`

- Arrow Row:
  - `~/.cargo/registry/src/.../arrow-row-56.2.0/src/lib.rs`
  - `~/.cargo/registry/src/.../arrow-row-56.2.0/src/fixed.rs`
  - `~/.cargo/registry/src/.../arrow-row-56.2.0/src/variable.rs`
  - `~/.cargo/registry/src/.../arrow-row-56.2.0/src/list.rs`

---

如需进一步补充（例如 descending / nulls_last 的完整示例、decimal/timestamp 等类型的编码细节），可以在此文档上继续扩展。
