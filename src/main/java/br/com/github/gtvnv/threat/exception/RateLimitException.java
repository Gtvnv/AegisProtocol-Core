package br.com.github.gtvnv.threat.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.TOO_MANY_REQUESTS) // Diz ao Spring que isso é um 429
public class RateLimitException extends RuntimeException {
    public RateLimitException(String message) {
        super(message);
    }
}