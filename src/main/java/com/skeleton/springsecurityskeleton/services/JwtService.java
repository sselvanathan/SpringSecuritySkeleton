package com.skeleton.springsecurityskeleton.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    @Value("${SECRET_KEY}")
    private String SECRET_KEY;
    public String extractUsername(String jwtToken) {
        return extractClaim(jwtToken, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractClaims(token);
        return claimsResolver.apply(claims);
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractClaims(String jwtToken) {
        Key signingKey = getSigningnKey();

        return Jwts
                .parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(jwtToken)
                .getBody();
    }

    public String generateToken(UserDetails userDetails){
        return generateTokenWithClaims(new HashMap<>(), userDetails);
    }

    public String generateTokenWithClaims(
            Map<String, Objects> claims,
            UserDetails userDetails
    ){
        long currentTimeMillis = System.currentTimeMillis();
        long expirationTimeMillis = 1000 * 60 * 60; //1h
        Date currentDate = new Date(currentTimeMillis);
        Date expirationDate = new Date(currentTimeMillis + expirationTimeMillis);
        return Jwts
                .builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(currentDate)
                .setExpiration(expirationDate)
                .signWith(getSigningnKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    private Key getSigningnKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}