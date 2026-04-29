package com.dark.gateway.config;

import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.SerializationUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Base64;

/**
 * 基于 Cookie 的 OAuth2 授权请求存储库。
 * 用于替代默认的内存 Session 存储，解决多实例环境下 Session 不一致导致的 authorization_request_not_found 错误。
 */
public class CookieOAuth2RequestRepository implements ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    public static final String AUTHORIZATION_REQUEST_COOKIE_NAME = "oauth2_auth_request";
    private static final Duration COOKIE_EXPIRE_DURATION = Duration.ofMinutes(5);

    @Override
    public Mono<OAuth2AuthorizationRequest> loadAuthorizationRequest(ServerWebExchange exchange) {
        return Mono.justOrEmpty(exchange.getRequest().getCookies().getFirst(AUTHORIZATION_REQUEST_COOKIE_NAME))
                .map(HttpCookie::getValue)
                .map(this::deserialize);
    }

    @Override
    public Mono<Void> saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, ServerWebExchange exchange) {
        if (authorizationRequest == null) {
            removeCookie(exchange);
            return Mono.empty();
        }

        String serializedRequest = serialize(authorizationRequest);
        ResponseCookie cookie = ResponseCookie.from(AUTHORIZATION_REQUEST_COOKIE_NAME, serializedRequest)
                .path("/")
                .httpOnly(true)
                .secure(true)
                .sameSite("Lax")
                .maxAge(COOKIE_EXPIRE_DURATION)
                .build();
        exchange.getResponse().addCookie(cookie);
        return Mono.empty();
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> removeAuthorizationRequest(ServerWebExchange exchange) {
        return loadAuthorizationRequest(exchange)
                .flatMap(request -> {
                    removeCookie(exchange);
                    return Mono.just(request);
                });
    }

    private void removeCookie(ServerWebExchange exchange) {
        ResponseCookie cookie = ResponseCookie.from(AUTHORIZATION_REQUEST_COOKIE_NAME, "")
                .path("/")
                .maxAge(0)
                .build();
        exchange.getResponse().addCookie(cookie);
    }

    private String serialize(OAuth2AuthorizationRequest request) {
        return Base64.getUrlEncoder().encodeToString(SerializationUtils.serialize(request));
    }

    private OAuth2AuthorizationRequest deserialize(String cookieValue) {
        try {
            return (OAuth2AuthorizationRequest) SerializationUtils.deserialize(Base64.getUrlDecoder().decode(cookieValue));
        } catch (Exception e) {
            return null;
        }
    }
}
