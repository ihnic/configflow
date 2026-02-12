# ConfigFlow 开发指南

这是一个现代化的代理配置管理平台，采用 Vue 3 + Flask 全栈架构。

## 项目概览

- **后端**: Python 3.11+ Flask API，模块化架构
- **前端**: Vue 3 + TypeScript + Element Plus + Vite
- **部署**: Docker + Nginx，支持 Sub-Store 订阅解析

## 开发环境设置

### 后端开发
```bash
cd backend
pip install -r requirements.txt
python app.py
```

### 前端开发
```bash
cd frontend
npm install
npm run dev
```

## 构建、测试、代码质量命令

### 前端 (Vue 3 + TypeScript)
```bash
# 开发服务器
npm run dev

# 生产构建
npm run build

# 预览构建结果
npm run preview
```

### 后端 (Flask)
```bash
# 启动开发服务器
python backend/app.py

# 生产环境（通过 Docker）
docker-compose up -d
```

### Docker 部署
```bash
# 标准部署
docker-compose up -d

# 包含 Sub-Store 的完整部署
docker-compose -f docker-compose.yml up -d

# All-in-One 部署
docker-compose -f docker-compose-aio.yml up -d
```

**注意**: 当前项目没有自动化测试套件和代码检查工具。建议添加以下工具以提高代码质量。

## 代码风格指南

### Python 后端代码规范

#### 导入规范
```python
# 标准库导入
import os
import logging
from datetime import datetime

# 第三方库导入
from flask import Flask, request, jsonify
import yaml

# 本地模块导入
from backend.common.auth import validate_token
from backend.routes import register_blueprints
```

#### 函数和类命名
- **函数**: `snake_case` - 例如 `get_local_ip()`, `generate_token()`
- **类**: `PascalCase` - 例如 `ConfigManager`, `AgentHandler`
- **常量**: `UPPER_SNAKE_CASE` - 例如 `JWT_SECRET_KEY`, `DEFAULT_PORT`
- **变量**: `snake_case` - 例如 `user_name`, `config_data`

#### 错误处理模式
```python
def api_function():
    try:
        data = request.json
        # 业务逻辑
        result = process_data(data)
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': 'Internal server error'}), 500
```

#### 日志记录
```python
from backend.utils.logger import get_logger

logger = get_logger(__name__)

def some_function():
    logger.info("Processing request")
    logger.debug(f"Data: {data}")
    logger.error(f"Error occurred: {str(e)}")
```

#### Flask 路由模式
```python
from flask import Blueprint

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['POST'])
def login():
    """用户登录"""
    pass
```

### TypeScript 前端代码规范

#### 导入规范
```typescript
// Vue 和第三方库
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import axios from 'axios'

// 本地模块
import type { Agent, Subscription } from '@/types'
import { api } from '@/api'
import StatCard from '@/components/StatCard.vue'
```

#### 接口定义
```typescript
// 使用 interface 定义对象结构
interface Agent {
  id: string
  name: string
  host: string
  port: number
  status: 'online' | 'offline'
}

// 使用 type 定义联合类型或复杂类型
type ServiceType = 'mihomo' | 'mosdns'
type Status = 'online' | 'offline' | 'error'
```

#### 组件模式 (Composition API)
```typescript
<script setup lang="ts">
import { ref, onMounted } from 'vue'

interface Props {
  agentId: string
  title?: string
}

interface Emits {
  update: [agent: Agent]
  delete: [id: string]
}

const props = withDefaults(defineProps<Props>(), {
  title: '默认标题'
})

const emit = defineEmits<Emits>()

const loading = ref(false)
const agents = ref<Agent[]>([])

onMounted(() => {
  loadAgents()
})
</script>
```

#### API 调用模式
```typescript
// 使用统一的 axios 实例
import { api } from '@/api'

export const agentApi = {
  // 获取所有 agents
  getAll: () => api.get<Agent[]>('/agents'),
  
  // 获取单个 agent
  getById: (id: string) => api.get<Agent>(`/agents/${id}`),
  
  // 创建 agent
  create: (data: Partial<Agent>) => api.post<Agent>('/agents', data),
  
  // 更新 agent
  update: (id: string, data: Partial<Agent>) => api.put<Agent>(`/agents/${id}`, data),
  
  // 删除 agent
  delete: (id: string) => api.delete(`/agents/${id}`)
}
```

#### 错误处理
```typescript
import { ElMessage } from 'element-plus'

try {
  await agentApi.create(formData)
  ElMessage.success('创建成功')
} catch (error) {
  console.error('创建失败:', error)
  ElMessage.error(error.response?.data?.message || '创建失败')
}
```

## 环境变量配置

### 后端环境变量
```bash
# 认证配置
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_password
JWT_SECRET_KEY=your-secret-key

# 数据目录
DATA_DIR=/data

# 日志级别
LOG_LEVEL=INFO

# Sub-Store 集成
SUB_STORE_URL=http://sub-store:3001
```

### 前端环境变量
在 `frontend/.env` 中配置：
```bash
VITE_API_BASE_URL=/api
VITE_APP_TITLE=ConfigFlow
```

## 项目结构说明

```
config-flow/
├── backend/                # Python Flask 后端
│   ├── app.py             # 主应用入口
│   ├── common/            # 公共模块 (认证、配置、工具)
│   ├── routes/            # API 路由模块
│   ├── converters/        # 配置生成器 (Mihomo/Surge/MosDNS)
│   ├── agents/            # Agent 管理模块
│   ├── utils/             # 工具函数模块
│   └── models/            # 数据模型
├── frontend/              # Vue 3 前端
│   └── src/
│       ├── views/         # 页面组件
│       ├── components/    # 公共组件
│       ├── api/           # API 调用封装
│       ├── types/         # TypeScript 类型定义
│       └── router/        # Vue Router 配置
├── docker/                # Docker 配置文件
├── doc/                   # 项目文档
└── .github/               # GitHub Actions 工作流
```

## 开发最佳实践

1. **模块化**: 保持代码模块化，每个文件职责单一
2. **类型安全**: 前端使用 TypeScript，后端添加类型注解
3. **错误处理**: 统一的错误处理和用户友好的错误消息
4. **API 设计**: RESTful API 设计，统一响应格式
5. **配置管理**: 使用环境变量管理敏感配置
6. **日志记录**: 适当的日志记录用于调试和监控
7. **代码注释**: 关键逻辑添加中文注释说明

## 推荐的开发工具

- **IDE**: VS Code + Vue Language Features (Volar) + Python 扩展
- **API 测试**: Postman 或 Insomnia
- **Docker 管理**: Docker Desktop
- **Git 客户端**: SourceTree 或命令行

## 部署注意事项

1. 生产环境务必修改默认密码和 JWT 密钥
2. 使用 HTTPS 保护 API 通信
3. 定期备份 `/data` 目录中的配置数据
4. 监控日志文件大小，设置日志轮转
5. 保持依赖库版本更新，及时修复安全漏洞