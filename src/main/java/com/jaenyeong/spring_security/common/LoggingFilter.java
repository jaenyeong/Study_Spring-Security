package com.jaenyeong.spring_security.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StopWatch;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class LoggingFilter extends GenericFilterBean {

	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		StopWatch stopWatch = new StopWatch();
		stopWatch.start(((HttpServletRequest) request).getRequestURI());

		// 체인에게 요청 처리
		// 다음 필터로 요청을 전달
		chain.doFilter(request, response);

		stopWatch.stop();
		logger.info(stopWatch.prettyPrint());
	}
}
