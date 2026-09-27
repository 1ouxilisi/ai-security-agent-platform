## 前言

传统的AI安全测试是人工手工测试：研究员手动构造Prompt，一个一个试。我们做了一个遗传算法Prompt进化引擎，用算法自动进化Payload，把人工测试效率提升了几十倍。这篇拆解原理。

---

## 一、为什么需要遗传算法

人工测试的问题：
- 一次只能测一个Payload
- 好的Payload靠经验，不可复制
- 覆盖范围有限
- 无法批量优化

遗传算法的优势：
- 自动探索24000种组合
- 适应度高的Payload自动保留
- 多代进化，越来越好
- 可以并行批量测试

---

## 二、基因设计

### 攻击策略基因（20种）
1. 忽略指令（Ignore Previous）
2. 角色扮演（Role Play）
3. 编码绕过（Encoding）
4. 多语言混合（Multilingual）
5. 续写诱导（Continuation）
6. 异常格式（Abnormal Format）
7. 翻译绕过（Translation）
8. 边界探测（Boundary Probe）
9. 记忆回溯（Memory Recall）
10. 代码注释（Code Comment）
11. 分块提取（Chunked Extraction）
12. 冲突诱导（Conflict Induction）
13. 条件绕过（Conditional Bypass）
14. 逻辑混淆（Logic Obfuscation）
15. 格式转换（Format Transformation）
16. 上下文注入（Context Injection）
17. 权威伪装（Authority Impersonation）
18. 紧急情况（Emergency Scenario）
19. 调试模式（Debug Mode）
20. 链式攻击（Chained Attack）

### 编码方式基因（12种）
1. 无编码
2. Base64
3. URL编码
4. Unicode编码
5. Hex编码
6. ROT13
7. 反向文本
8. 空格替换
9. 零宽字符
10. HTML实体
11. JSON转义
12. 多层嵌套编码

### 包装方法基因（10种）
1. 直接输出
2. JSON格式包装
3. Markdown代码块
4. 引号包裹
5. 注释包裹
6. 表格格式
7. 列表格式
8. 对话格式
9. 邮件格式
10. 报告格式

### 目标类型基因（10种）
1. 提取系统提示
2. 绕过安全过滤
3. 执行恶意指令
4. 泄露训练数据
5. 生成恶意代码
6. 执行SQL注入
7. 绕过内容审核
8. 生成钓鱼内容
9. 泄露API密钥
10. 执行未授权操作

---

## 三、进化流程

```
第一代：随机生成100个个体（Payload）
    ↓
适应度评估：每个Payload测试目标模型，打分
    ↓
选择：保留适应度最高的20个个体
    ↓
交叉：两个个体的基因随机组合，生成新个体
    ↓
变异：随机改变某个基因（5%概率）
    ↓
第二代：100个新个体
    ↓
重复20代...
    ↓
最终：输出适应度最高的Top 10 Payload
```

---

## 四、适应度函数

一个Payload的得分由以下因素决定：

| 因素 | 权重 | 说明 |
|------|------|------|
| 是否成功绕过 | 40% | 模型是否执行了恶意指令 |
| 是否泄露敏感信息 | 30% | 是否提取到系统提示/密钥 |
| 输出是否完整 | 15% | 结果是否完整可用 |
| 隐蔽程度 | 10% | 是否被安全检测标记 |
| 通用性 | 5% | 是否适用于多个模型 |

---

## 五、实战效果

在测试一个开源LLM应用时：

| 代数 | 最优适应度 | 成功率 |
|------|-----------|--------|
| 第1代 | 20/100 | 5% |
| 第5代 | 55/100 | 25% |
| 第10代 | 78/100 | 50% |
| 第15代 | 88/100 | 65% |
| 第20代 | 92/100 | 72% |

20代进化后，成功率从5%提升到72%。

人工测试通常只能找到2-3个有效Payload，遗传算法自动发现了30+个。

---

## 六、工程实现

核心代码结构：

```python
class GeneticPromptEvolver:
    def __init__(self, target_model, gene_pool, population=100):
        self.target = target_model
        self.genes = gene_pool  # 4类基因
        self.population = population
        self.generation = 0
        
    def generate_individual(self):
        """随机生成一个个体"""
        return {
            'strategy': random.choice(self.genes['strategies']),
            'encoding': random.choice(self.genes['encodings']),
            'wrapper': random.choice(self.genes['wrappers']),
            'target': random.choice(self.genes['targets'])
        }
    
    def evaluate(self, individual):
        """适应度评估"""
        prompt = self.build_prompt(individual)
        response = self.target.query(prompt)
        score = self.calc_fitness(response, individual['target'])
        return score
    
    def crossover(self, parent1, parent2):
        """交叉"""
        child = {}
        for key in parent1:
            child[key] = random.choice([parent1[key], parent2[key]])
        return child
    
    def mutate(self, individual, rate=0.05):
        """变异"""
        if random.random() < rate:
            gene_key = random.choice(list(individual.keys()))
            individual[gene_key] = random.choice(self.genes[gene_key + 's'])
        return individual
```

---

## 七、应用场景

1. **SRC漏洞挖掘**：自动测试AI应用漏洞
2. **安全评估**：批量测试企业AI应用安全性
3. **红队演练**：模拟高级AI攻击
4. **防护测试**：测试自己的AI防护是否有效

---

## 免责声明

本文仅用于授权环境的AI安全研究和红队测试。未经授权对他人AI系统进行测试属于违法行为。测试前必须获得书面授权。
