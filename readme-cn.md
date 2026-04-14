# burp2har

> **注意 / Note:** 此中文文档已过时。请参阅最新的英文文档：[README.md](./readme.md)
>
> This Chinese README is outdated. Please refer to the up-to-date English documentation: [README.md](./readme.md)

---

`burp2har` 是一个基于 Python 的命令行工具，用于将 Burp Suite 导出的 HTTP 流量（XML 格式）转换为标准 HAR（HTTP Archive）格式。

## 快速开始

```bash
# 安装
pip install git+https://github.com/xlory04/Burpsuite-HAR-Converter.git

# 转换
burp2har convert export.xml

# 验证 XML 格式
burp2har validate export.xml

# 查看文件统计
burp2har info export.xml

# 检查并安装更新
burp2har update

# 帮助
burp2har help
```

详细文档请参阅：[README.md](./readme.md)
