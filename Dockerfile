# ==========================================
# 第一阶段：构建应用
# ==========================================
FROM amazoncorretto:17-alpine3.17 AS build

# 安装 Maven
RUN apk add --no-cache maven

WORKDIR /app

# 缓存依赖
COPY pom.xml .
RUN mvn dependency:go-offline -B

# 复制源代码并构建
COPY src ./src
RUN mvn clean package -DskipTests

# ==========================================
# 第二阶段：运行应用 (改用带 Shell 的镜像)
# ==========================================
FROM eclipse-temurin:17-jre 

WORKDIR /app

# 1. 创建非 root 用户并安装 curl (用于健康检查)
RUN apt-get update && apt-get install -y curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r appgroup && useradd -r -g appgroup appuser

# 2. 从构建阶段复制 jar 包
COPY --from=build /app/target/ms-java-gateway*.jar /app/ms-java-gateway.jar

# 3. 复制并设置 entrypoint.sh
COPY entrypoint.sh /app/entrypoint.sh

# 4. 赋予执行权限 (同时处理可能的 Windows 换行符问题)
RUN chmod +x /app/entrypoint.sh && \
    sed -i 's/\r$//' /app/entrypoint.sh

# 设置环境变量
ENV JAVA_OPTS="-Xmx128m -Xms128m -Xss256k -XX:+UseSerialGC -XX:MaxMetaspaceSize=64m -XX:TieredStopAtLevel=1 -Djava.security.egd=file:/dev/./urandom"
ENV APP_PORT=8281

# 声明端口
EXPOSE $APP_PORT

# 5. 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${APP_PORT}/actuator/health || exit 1

# 切换到非 root 用户
USER appuser

# 6. 设置启动命令
ENTRYPOINT ["/app/entrypoint.sh"]

CMD ["sh", "-c", "java $JAVA_OPTS -jar /app/ms-java-gateway.jar"]
