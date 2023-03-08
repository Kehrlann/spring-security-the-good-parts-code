package wf.garnier.spring.security.thegoodparts;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Objects;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

class RobotAccountFilter extends OncePerRequestFilter {
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		// 1. Should the filter be applied ?
		if (!Collections.list(request.getHeaderNames()).contains("x-robot-password")) {
			filterChain.doFilter(request, response);
			return;
		}

		// 2. Authenticate or reject
		if (Objects.equals(request.getHeader("x-robot-password"), "beep-boop")) {
			var auth = new RobotAuthentication();
			var newContext = SecurityContextHolder.createEmptyContext();
			newContext.setAuthentication(auth);
			SecurityContextHolder.setContext(newContext);
		} else {
			response.setStatus(HttpStatus.FORBIDDEN.value());
			response.setCharacterEncoding(StandardCharsets.UTF_8.name());
			response.setContentType("text/plain;charset=utf-8");
			response.getWriter().write("You are not Ms Robot 🤖");
			response.getWriter().close();
			return;
		}

		// 3. Continue
		filterChain.doFilter(request, response);
	}
}
