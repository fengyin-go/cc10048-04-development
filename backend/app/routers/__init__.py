"""业务路由汇总：所有模块共用一套资源路由，由领域服务完成分派。"""
from __future__ import annotations

from app.routers import governance, resource

# governance 使用固定前缀 /api/governance，需要先于通用资源路由注册，单独在 main 中挂载。
ROUTERS = [resource]
