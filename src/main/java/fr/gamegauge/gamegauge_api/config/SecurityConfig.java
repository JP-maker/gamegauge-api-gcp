package fr.gamegauge.gamegauge_api.config;

import fr.gamegauge.gamegauge_api.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;


/**
 * Configuration principale de la sécurité pour l'application GameGauge.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final UserDetailsService userDetailsService;

    // Liste des URLs publiques
    private static final String[] PUBLIC_URLS = {
            "/api/auth/**",
            // -- Supervision (Prometheus, sondes Kubernetes) --
            "/actuator/**",
            // -- Swagger UI v3 (OpenAPI) --
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html"
    };

    // Mettre à jour le constructeur
    public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Bean qui définit le fournisseur d'authentification.
     * Il lie le UserDetailsService (qui charge l'utilisateur) et le PasswordEncoder (qui compare les mots de passe).
     *
     * @return Le fournisseur d'authentification configuré.
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    /**
     * Bean qui expose l'AuthenticationManager de Spring.
     * Nous l'utiliserons dans notre AuthService pour déclencher le processus d'authentification.
     *
     * @param config La configuration d'authentification.
     * @return L'AuthenticationManager.
     * @throws Exception en cas d'erreur de configuration.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthFilter jwtAuthFilter) throws Exception {
        http
                .cors(withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(PUBLIC_URLS).permitAll()
                        .anyRequest().authenticated()
                )
                // Configurer la gestion de session pour qu'elle soit stateless.
                // Le serveur ne créera ni n'utilisera de session HTTP.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider())
                // Ajouter notre filtre JWT avant le filtre de base de Spring Security.
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Bean pour configurer la politique CORS de manière globale pour l'application.
     * C'est ici que nous autorisons notre frontend Angular.
     *
     * @return la source de configuration CORS.
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // 2. Spécifier l'origine autorisée (votre application Angular)
        configuration.setAllowedOrigins(List.of("http://localhost:4200", "https://gamegauge.fr"));

        // 3. Spécifier les méthodes HTTP autorisées (GET, POST, etc.)
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));

        // 4. Spécifier les en-têtes autorisés
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With"));

        // 5. Autoriser les 'credentials' (comme les cookies ou les en-têtes d'autorisation)
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Appliquer cette configuration à toutes les routes de notre API
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}