#!/bin/sh

# Nacos 客户端 JVM 配置
export JAVA_TOOL_OPTIONS="${JAVAJAVA_TOOL_OPTIONS_OPTS} \
  -Duser.home=/tmp \
  -Djm.snapshot.path=/tmp/nacos \
  -Dcom.alibaba.nacos.client.naming.cache.dir=/tmp/nacos \
  -Dnacos.remote.client.grpc.channel.capability.negotiation.timeout=10000 \
  -Dnacos.remote.client.grpc.server.check.timeout=10000 \
  -Dnacos.remote.client.grpc.timeout=10000"

# 打印启动信息
echo "=========================================================="
echo "Starting Application..."
echo "JAVA_OPTS: $JAVA_OPTS"
echo "=========================================================="

# 执行传入的命令 (即 Dockerfile CMD 中的内容)
exec "$@"
