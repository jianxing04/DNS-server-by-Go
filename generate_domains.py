import random
import numpy as np

# 1. 准备不同权重的域名库
top_domains = [
    "www.baidu.com", "api.m.taobao.com", "v.douyin.com", "wx.qlogo.cn",
    "static.tieba.baidu.com", "gateway.messenger.wsc.qq.com", "p3-dy.byteimg.com",
    "f-log.byteoversea.com", "conf.p.p-s.microsoft.com", "safebrowsing.googleapis.com"
]

common_domains = [
    "github.com", "stackoverflow.com", "bilibili.com", "zhihu.com", 
    "segmentfault.com", "csdn.net", "v2ex.com", "weibo.com"
]

# 2. 模拟长尾效应（生成一些随机的、不重复的域名来测试 Cache Miss）
long_tail_domains = [f"user-sub-{i}.example-tail.com" for i in range(5000)]

# 3. 设置查询类型比例
qtypes = ["A"] * 85 + ["AAAA"] * 10 + ["MX"] * 3 + ["CNAME"] * 2

def generate_queries(filename, count=1000000):
    with open(filename, 'w') as f:
        # 使用 Zipf 分布生成索引
        # a=1.2 是比较接近互联网流量特征的参数
        indices = np.random.zipf(a=1.2, size=count)
        
        all_domains = top_domains + common_domains + long_tail_domains
        num_all = len(all_domains)
        
        for idx in indices:
            # 确保索引不越界
            d_idx = (idx - 1) % num_all
            domain = all_domains[d_idx]
            qtype = random.choice(qtypes)
            f.write(f"{domain} {qtype}\n")

if __name__ == "__main__":
    print("🚀 正在生成符合真实分布的 100 万条 DNS 请求数据...")
    generate_queries("queries.txt")
    print("✅ 生成完成: queries.txt")
