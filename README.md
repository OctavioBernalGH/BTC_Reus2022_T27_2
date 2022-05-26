<table>
<tr>
<td width="100px"><img src="https://user-images.githubusercontent.com/103035621/170483040-a88d598b-145b-4903-accb-948ceff05811.png" alt="Team MSKA"/></td>
<td width="1100px"> <h2>MSKA: Spring + JPA + MYSQL + Spring Security UD27_Ejercicio-2</h2> </td>

</tr>
</table>

[![Java](https://img.shields.io/badge/Java-FrontEnd-informational)]()
[![GitHub](https://img.shields.io/badge/GitHub-Repository-lightgrey)]()
[![SQL](https://img.shields.io/badge/SQL-DataBase-yellowgreen)]()
[![Spring](https://img.shields.io/badge/Spring-infrastructure-brightgreen)]()
[![Maven](https://img.shields.io/badge/Maven-ProjectStructure-blueviolet)]()

Este ejercicio ha sido realizado por los miembros del equipo 1. Dicho equipo esta formado por:

[- Ixabel Justo Etxeberria](https://github.com/Kay-Nicte)<br>
[- J.Oriol López Bosch](https://github.com/mednologic)<br>
[- Octavio Bernal](https://github.com/OctavioBernalGH)<br>
[- David Dalmau](https://github.com/DavidDalmauDieguez)

<p align="justify">Se crea un proyecto Maven utilizando como base el ejercicio 26, y se le aplica la seguridad.</p>

A continuación se expondrá el desarrollo completo de la aplicación. 

Tanto la base de datos utilizada como las clases son, como digo, las mismas que en el ejercicio 26, por lo que toda la información de base podrás encontrarla en su respositorio correspondiente: [Ejercicio 2 UD26](https://github.com/mednologic/BTC_Reus2022_TA26_2/blob/main/README.md). De todas formas, se ha añadido una nueva tabla llamada <i>usuario</i>:

```sql
use UD26_Ejercicio_2;

create table usuario 
(
id int auto_increment,
password varchar(255), 
role varchar(255), 
username varchar(255),
primary key (id)
);

INSERT INTO usuario (username, password, role) 
VALUES ('admin', '$2a$10$XURPShQNCsLjp1ESc2laoObo9QZDhxz73hJPaEv7/cBha4pk0AgP.','admin');
``` 

## Verificación funcionamiento mediante Postman.

Mediante el método http:POST y enviando por body el usuario y contraseña, se realiza la autenticación. Spring Security retornará un <i>bearer token</i> para completar la identificación y acceder como administración al aplicativo:

![1 login](https://user-images.githubusercontent.com/103035621/170501257-cd27f966-56d3-40e3-abdb-541e6eead6f9.PNG)

Los siguientes pasos serán:

	· Entrar a la pestaña Authorization
	· En Type seleccionar "Bearer Token
	· En Token, a mano derecha, pegar el nuevo token que se nos ha generado (este nos servirá para toda la sesión)

![2 bearing](https://user-images.githubusercontent.com/103035621/170501295-6060269e-b050-4d40-98d9-2687e0a10e6a.PNG)

Mediante el método http:GET, apuntando al <i>endpoint</i> /users/ el aplitativo nos devolverá el listado de usuarios albergados en la base de datos, de tal forma que podremos comprobar su correcto funcionamiento:

![3 consultar usuarios](https://user-images.githubusercontent.com/103035621/170501350-015e9701-0cdf-41e3-bba8-fc2700d3b2bc.PNG)

Mediante el método http:POST y apuntando el mismo <i>endpoint</i> anterior, se introducirá en el <i>body</i> un nuevo usuario a añadir en la BBDD.
Además, como se puede observar en parte inferior, la contraseña aparece encriptada automáticamente mediante #64:

![4 creacion nuevo user](https://user-images.githubusercontent.com/103035621/170501373-c10368b6-beb4-41e5-b875-967a5a7fac7d.PNG)

Mediante el método http:DELETE, apuntando siempre al mismo <i>endpoint</i> e introcudiendo el identificador en la ruta, se procederá a eliminar el usuario deseado:

![6 eliminar usuario ID](https://user-images.githubusercontent.com/103035621/170501388-921bb863-9800-4f6c-8a0a-73d46b88a03a.PNG)

Con el método http:GET, podemos buscar un usuario concreto mediante su nombre de usuario en la ruta:

![5 buscar usuario nombre](https://user-images.githubusercontent.com/103035621/170501425-d955f23a-6957-4bf5-8a36-a5ad212a8bd3.PNG)

## Ejecución del ejercicio.

Para realizar este ejercicio, se añade Spring Security al ejemplo de la UD26_Ejercicio_2, para ello primero de todo se creará el siguiente POM. A continuación se muestra el código POM generado añadiendo la seguridad:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.7.0</version>
		<relativePath /> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.crud.spring</groupId>
	<artifactId>UD26-Ejercicio_2</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<packaging>war</packaging>
	<name>UD26-Ejercicio_2</name>
	<description>Ejercicio UD26</description>
	<properties>
		<java.version>1.8</java.version>
	</properties>
	<dependencies>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-data-jpa</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-devtools</artifactId>
			<scope>runtime</scope>
			<optional>true</optional>
		</dependency>
		<!-- https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt -->
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt</artifactId>
			<version>0.9.1</version>
		</dependency>

		<dependency>
			<groupId>mysql</groupId>
			<artifactId>mysql-connector-java</artifactId>
			<scope>runtime</scope>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-tomcat</artifactId>
			<scope>provided</scope>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
			<exclusions>
				<exclusion>
					<groupId>org.junit.vintage</groupId>
					<artifactId>junit-vintage-engine</artifactId>
				</exclusion>
			</exclusions>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-data-jpa</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.security</groupId>
			<artifactId>spring-security-test</artifactId>
			<scope>test</scope>
		</dependency>
	</dependencies>


	<build>
		<plugins>
			<plugin>
				<groupId>org.apache.maven.plugins</groupId>
				<artifactId>maven-resources-plugin</artifactId>
				<version>3.1.0</version><!--$NO-MVN-MAN-VER$ -->
			</plugin>
		</plugins>
	</build>

</project>
```

Se configurará el application.propierties para tener acceso a la base de datos utilizada en el anterior ejercicio y donde se creará la tabla de usuarios que albergará los diferentes usuarios con los roles y contraseña.

```sql
# Driver de la BBDD del tipo MYSQL
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
# Direccion de la BBDD en local con el esquema a utilizar
spring.datasource.url=jdbc:mysql://192.168.1.123:3306/UD26_Ejercicio_2
# Se define el usuario de la BBDD
spring.datasource.username=remote
# Se define la contraseña del usuario de la BBDD
spring.datasource.password=Reus_2022
# Se muestran las instrucciones de JPA sobre la BBDD en consola
spring.jpa.show-sql=true
spring.jpa.open-in-view=true
# spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.MySQL5Dialect
# spring.jpa.hibernate.ddl-auto=update
# Puerto del servidor Tomcat para endpoints.
server.port=8181
```

A continuación se creará la base de datos de usuario para la autenticación, para ello se ha generado el siguiente script:

```sql
use UD26_Ejercicio_2;

create table usuario 
(
id int auto_increment,  
password varchar(255), 
role varchar(255), 
username varchar(255),
primary key (id)
);

INSERT INTO usuario (username, password, role) VALUES ('admin', '$2a$10$XURPShQNCsLjp1ESc2laoObo9QZDhxz73hJPaEv7/cBha4pk0AgP.','admin');
```

A continuación se procederá con la creación de la entidad usuario que irá mapeada con la tabla de la base de datos referente a los usuarios, para ello hay que dirigirse al dto y crear la clase usuario:

<h3>Usuario DTO:</h3>
<details>

<summary>Código generado</summary>

<br>

```java
package com.mska.spring.dto;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "usuario")
public class Usuario {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;
	
	@Column(name = "username")
	private String username;
	
	@Column(name = "password")
	private String password;
	
	@Column(name = "role")
	private String role;	
	
	/**
	 * 
	 */
	public Usuario() {
		super();
	}

	/**
	 * @param id
	 * @param username
	 * @param password
	 * @param role
	 */
	public Usuario(long id, String username, String password, String role) {
		super();
		this.id = id;
		this.username = username;
		this.password = password;
		this.role = role;
	}

	public long getId() {
		return id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getRole() {
		return role;
	}

	public void setRole(String role) {
		this.role = role;
	}
	
	
}
```
</details>

El siguiente procedimiento corresponde a la creación de la interfaz DTO, la cuál heredará de JpaRepository los métodos CRUD básicos.

<h3>Usuario DAO</h3>
<details>

<summary>Código generado</summary>

<br>

```java
package com.mska.spring.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import com.mska.spring.dto.Usuario;

public interface IUsuarioDAO extends JpaRepository<Usuario, Long> {

	Usuario findByUsername(String username);
}
 ```
</details>

El siguiente procedimiento a seguir será la definición de métodos en la capa service, en este caso se crea únicamente la clase UsuarioServiceImpl donde se definirán los métodos necesarios que se inyectarán en el controlador de usuario. Para ello se genera el siguiente código.

<h3>Usuario Service</h3>
<details>

<summary>Código generado</summary>

<br>

```java
package com.mska.spring.service;

import static java.util.Collections.emptyList;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.mska.spring.dao.IUsuarioDAO;
import com.mska.spring.dto.Usuario;

@Service
public class UsuarioDetailsServiceImpl implements UserDetailsService {

	private IUsuarioDAO iUsuarioDAO;

	public UsuarioDetailsServiceImpl(IUsuarioDAO iUsuarioDAO) {
		this.iUsuarioDAO = iUsuarioDAO;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Usuario usuario = iUsuarioDAO.findByUsername(username);
		if (usuario == null) {
			throw new UsernameNotFoundException(username);
		}
		return new User(usuario.getUsername(), usuario.getPassword(), emptyList());
	}
	
}
```
</details>
  
A continuación se define la capa de seguridad en el paquete service, se crean las clases necesarias para el correcto funcionamiento del aplicativo, dicha seguridad encriptará la contraseña con HASH64 n veces, y gestionará el acceso y registro de nuevos usuarios mediante el bearer token generado al loguearse.
  
<h3>Usuario Security</h3>
  
<details>

<summary>Código generado  </summary>
  
<br>
  
```java

```
  
</details>
  
<details>

<summary>Código generado Constants</summary>
  
<br>
  
```java
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
```
  
</details>
  
  <details>

<summary>Código generado  JWTAuthenticationFilter</summary>
  
<br>
  
```java
package com.mska.spring.security;

import static com.mska.spring.security.Constants.HEADER_AUTHORIZACION_KEY;
import static com.mska.spring.security.Constants.ISSUER_INFO;
import static com.mska.spring.security.Constants.SUPER_SECRET_KEY;
import static com.mska.spring.security.Constants.TOKEN_BEARER_PREFIX;
import static com.mska.spring.security.Constants.TOKEN_EXPIRATION_TIME;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.mska.spring.dto.Usuario;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private AuthenticationManager authenticationManager;

	public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		try {
			Usuario credenciales = new ObjectMapper().readValue(request.getInputStream(), Usuario.class);

			return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
					credenciales.getUsername(), credenciales.getPassword(), new ArrayList<>()));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication auth) throws IOException, ServletException {

		String token = Jwts.builder().setIssuedAt(new Date()).setIssuer(ISSUER_INFO)
				.setSubject(((User)auth.getPrincipal()).getUsername())
				.setExpiration(new Date(System.currentTimeMillis() + TOKEN_EXPIRATION_TIME))
				.signWith(SignatureAlgorithm.HS512, SUPER_SECRET_KEY).compact();
		response.addHeader(HEADER_AUTHORIZACION_KEY, TOKEN_BEARER_PREFIX + " " + token);//devuelve token por cabecera
		response.getWriter().write("{\"token\": \"" + token + "\"}");//devuelve token por body
		System.out.println(response.getHeader(HEADER_AUTHORIZACION_KEY));
	
	}
	
	
	
}

```
  
</details>
  
<details>

<summary>Código generado  JWTAuthorizationFilter</summary>

<br>

```java
package com.mska.spring.security;

import static com.mska.spring.security.Constants.HEADER_AUTHORIZACION_KEY;
import static com.mska.spring.security.Constants.SUPER_SECRET_KEY;
import static com.mska.spring.security.Constants.TOKEN_BEARER_PREFIX;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Jwts;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	public JWTAuthorizationFilter(AuthenticationManager authManager) {
		super(authManager);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		String header = req.getHeader(HEADER_AUTHORIZACION_KEY);
		if (header == null || !header.startsWith(TOKEN_BEARER_PREFIX)) {
			chain.doFilter(req, res);
			return;
		}
		UsernamePasswordAuthenticationToken authentication = getAuthentication(req);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(req, res);
	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		String token = request.getHeader(HEADER_AUTHORIZACION_KEY);
		if (token != null) {
			// Se procesa el token y se recupera el usuario.
			String user = Jwts.parser()
						.setSigningKey(SUPER_SECRET_KEY)
						.parseClaimsJws(token.replace(TOKEN_BEARER_PREFIX, ""))
						.getBody()
						.getSubject();

			if (user != null) {
				return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
			}
			return null;
		}
		return null;
	}
}
```

</details>
    
    

<details>

<summary>Código generado  SimpleCORSFilter</summary>

<br>

```java
package com.mska.spring.security;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class SimpleCORSFilter implements Filter {

private final Logger log = LoggerFactory.getLogger(SimpleCORSFilter.class);

public SimpleCORSFilter() {
    log.info("SimpleCORSFilter init");
}

@Override
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {

    HttpServletRequest request = (HttpServletRequest) req;
    HttpServletResponse response = (HttpServletResponse) res;

    response.setHeader("Access-Control-Allow-Origin", request.getHeader("Origin"));
    response.setHeader("Access-Control-Allow-Credentials", "true");
    response.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE");
    response.setHeader("Access-Control-Max-Age", "3600");
    response.setHeader("Access-Control-Allow-Headers", "Content-Type, Accept, X-Requested-With, remember-me, Host, Content-Lenght");

    chain.doFilter(req, res);
}




@Override
public void init(FilterConfig filterConfig) {
}

@Override
public void destroy() {
}

}
```

</details>
    
    
  
  
  
<details>

<summary>Código generado  WebSecurity</summary>

<br>

```java
package com.mska.spring.security;

import static com.mska.spring.security.Constants.LOGIN_URL;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

	private UserDetailsService userDetailsService;

	public WebSecurity(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception {
		/*
		 * 1. Se desactiva el uso de cookies
		 * 2. Se activa la configuración CORS con los valores por defecto
		 * 3. Se desactiva el filtro CSRF
		 * 4. Se indica que el login no requiere autenticación
		 * 5. Se indica que el resto de URLs esten securizadas
		 */
		httpSecurity
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
			.cors().and()
			.csrf().disable()
			.authorizeRequests().antMatchers(HttpMethod.POST, LOGIN_URL).permitAll()
			.anyRequest().authenticated().and()
				.addFilter(new JWTAuthenticationFilter(authenticationManager()))
				.addFilter(new JWTAuthorizationFilter(authenticationManager()));
	}

	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		// Se define la clase que recupera los usuarios y el algoritmo para procesar las passwords
		auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
		return source;
	}
}

```

</details>
  
Por último se tendrá que añadir el código referente a los endpoints del usuario, para ello se creará la clase UsuarioController y se rellenarán los métodos con la ruta seguido del método HTTP utilizado. El código generado sería el siguiente:
  
<h3>Usuario Controller</h3>
  
<details>
  
<summary>Código generado</summary>
  
<br>
  
```java
package com.mska.spring.controllers;

import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.mska.spring.dao.IUsuarioDAO;
import com.mska.spring.dto.Usuario;


@RestController
@CrossOrigin(origins = "*", methods= {RequestMethod.GET,RequestMethod.POST,RequestMethod.PUT,RequestMethod.DELETE})
public class UsuarioController {

	private IUsuarioDAO iUsuarioDAO;

	private BCryptPasswordEncoder bCryptPasswordEncoder;

	public UsuarioController(IUsuarioDAO iUsuarioDAO, BCryptPasswordEncoder bCryptPasswordEncoder) {
		this.iUsuarioDAO = iUsuarioDAO;
		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
	}
	
	
	@GetMapping("/response-entity-builder-with-http-headers")
	public ResponseEntity<String> usingResponseEntityBuilderAndHttpHeaders() {
	    HttpHeaders responseHeaders = new HttpHeaders();
	    responseHeaders.set("Baeldung-Example-Header", 
	      "Value-ResponseEntityBuilderWithHttpHeaders");

	    return ResponseEntity.ok()
	      .headers(responseHeaders)
	      .body("Response with header using ResponseEntity");
	}
	
	@PostMapping("/users/")
	public Usuario saveUsuario(@RequestBody Usuario user) {
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		iUsuarioDAO.save(user);
		return user;
	}

	@GetMapping("/users/")
	public List<Usuario> getAllUsuarios() {
		return iUsuarioDAO.findAll();
	}

	@GetMapping("/users/{username}")
	public Usuario getUsuario(@PathVariable String username) {
		return iUsuarioDAO.findByUsername(username);
	}
	
	@DeleteMapping("/users/{id}")
	public String eliminarUser(@PathVariable(name="id")long id) {
		iUsuarioDAO.deleteById(id);
		return "User deleted.";
	}

}
```
  
</details>
