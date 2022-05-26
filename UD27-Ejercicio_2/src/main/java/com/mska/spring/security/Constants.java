package com.mska.spring.security;

public class Constants {

	/** Crecenciales spring security */
	public static final String LOGIN_URL = "/login";
	public static final String HEADER_AUTHORIZACION_KEY = "Authorization";
	public static final String TOKEN_BEARER_PREFIX = "Bearer";
	
	/** Atributos de conexión JWT */
	public static final String ISSUER_INFO = "Octavio Bernal";
	public static final String SUPER_SECRET_KEY = "1234";
	public static final long TOKEN_EXPIRATION_TIME = 864_000_000;
}
