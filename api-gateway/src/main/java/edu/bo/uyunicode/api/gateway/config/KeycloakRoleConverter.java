package edu.bo.uyunicode.api.gateway.config;


import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Flux;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class KeycloakRoleConverter implements Converter<Jwt, Flux<GrantedAuthority>> {
    @Nullable
    @Override
    public Flux<GrantedAuthority> convert(Jwt source) {
        Map<String, Object> realmAccess = source.getClaim("realm_access");
        if (realmAccess == null || realmAccess.isEmpty())
            return Flux.empty();
        Collection<String> roles = (Collection<String>) realmAccess.get("roles");
        if (roles == null || roles.isEmpty())
            return Flux.empty();
        // Spring Security espera que los roles tengan el prefijo "ROLE_"
        List<GrantedAuthority> authorities = roles.stream()
                .map(roleName -> "ROLE_" + roleName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        return Flux.fromIterable(authorities);
    }

    @Override
    public <U> Converter<Jwt, U> andThen(Converter<? super Flux<GrantedAuthority>, ? extends U> after) {
        return Converter.super.andThen(after);
    }
}
