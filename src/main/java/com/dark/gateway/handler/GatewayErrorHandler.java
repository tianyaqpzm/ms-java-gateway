package com.dark.gateway.handler;

import java.time.Instant;
import java.util.Map;

import org.springframework.boot.autoconfigure.web.WebProperties;
import org.springframework.boot.autoconfigure.web.reactive.error.AbstractErrorWebExceptionHandler;
import org.springframework.boot.web.reactive.error.ErrorAttributes;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;

import com.dark.gateway.filter.TraceIdFilter;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * 统一网关错误处理器：返回标准化 JSON 错误响应，绝不暴露后端堆栈信息。
 */
@Slf4j
@Component
@Order(-1)
public class GatewayErrorHandler extends AbstractErrorWebExceptionHandler {

    public GatewayErrorHandler(ErrorAttributes errorAttributes,
                               WebProperties webProperties,
                               ApplicationContext applicationContext,
                               ServerCodecConfigurer serverCodecConfigurer) {
        super(errorAttributes, webProperties.getResources(), applicationContext);
        super.setMessageWriters(serverCodecConfigurer.getWriters());
        super.setMessageReaders(serverCodecConfigurer.getReaders());
    }

    @Override
    protected RouterFunction<ServerResponse> getRoutingFunction(ErrorAttributes errorAttributes) {
        return RouterFunctions.route(RequestPredicates.all(), this::renderErrorResponse);
    }

    private Mono<ServerResponse> renderErrorResponse(ServerRequest request) {
        Throwable error = getError(request);

        HttpStatusCode statusCode = determineHttpStatus(error);
        int statusValue = statusCode.value();
        String reasonPhrase = statusCode instanceof HttpStatus httpStatus
                ? httpStatus.getReasonPhrase()
                : "Error";

        String traceId = request.headers().firstHeader(TraceIdFilter.TRACE_ID_HEADER);

        log.error("【网关异常】{} {} -> {} traceId={}, error={}",
                request.method(), request.path(), statusValue,
                traceId != null ? traceId : "N/A", error.getMessage());

        Map<String, Object> errorBody = Map.of(
                "traceId", traceId != null ? traceId : "",
                "status", statusValue,
                "error", reasonPhrase,
                "message", sanitizeMessage(error),
                "path", request.path(),
                "timestamp", Instant.now().toString()
        );

        return ServerResponse.status(statusCode)
                .contentType(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(errorBody));
    }

    private HttpStatusCode determineHttpStatus(Throwable error) {
        if (error instanceof org.springframework.web.server.ResponseStatusException rse) {
            return rse.getStatusCode();
        }
        if (error instanceof java.util.concurrent.TimeoutException) {
            return HttpStatus.GATEWAY_TIMEOUT;
        }
        return HttpStatus.BAD_GATEWAY;
    }

    /**
     * 清洗异常消息，避免暴露内部堆栈信息给前端。
     */
    private String sanitizeMessage(Throwable error) {
        if (error instanceof java.util.concurrent.TimeoutException) {
            return "Service response timeout";
        }
        if (error instanceof java.net.ConnectException) {
            return "Service temporarily unavailable";
        }
        String message = error.getMessage();
        if (message != null && message.length() > 200) {
            return message.substring(0, 200) + "...";
        }
        return message != null ? message : "Unexpected gateway error";
    }
}
