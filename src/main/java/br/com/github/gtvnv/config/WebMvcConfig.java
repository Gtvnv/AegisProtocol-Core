package br.com.github.gtvnv.config;

import br.com.github.gtvnv.config.interceptor.AegisSecurityInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    private final AegisSecurityInterceptor aegisSecurityInterceptor;

    public WebMvcConfig(AegisSecurityInterceptor aegisSecurityInterceptor) {
        this.aegisSecurityInterceptor = aegisSecurityInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // Aplica o interceptor em todas as rotas da API
        registry.addInterceptor(aegisSecurityInterceptor)
                .addPathPatterns("/api/**"); // Só intercepta o que for /api/...
    }
}