package com.example.hrm.security.jwt;

import com.example.hrm.security.UserDetailServiceCustom;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtProvider jwtProvider;
    private final UserDetailServiceCustom userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException
    {
        // 1. Lấy token từ header "Authorization: Bearer <token>"
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            // không có token: đi tiếp, sẽ bị chặn ở bước phân quyền
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.substring(7);

        try {
            // 2. Validate (chữ ký + hết hạn) và lấy username
            String username = jwtProvider.extractUsername(token);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // 3. Load UserDetails
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                if (jwtProvider.isTokenValid(token, userDetails)) {
                    // 4. Tạo Authentication và gán vào SecurityContext
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                                    userDetails, null, userDetails.getAuthorities()
                    );
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        } catch (Exception e) {
            // token sai chữ ký, hết hạn, user không tồn tại...: bỏ qua, không đăng nhập
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }
}
