# Projeto JWT com Spring Boot e Java 17

Em nosso projeto, vamos criar uma Api Rest com autenticação de segurança com Spring Security e JWT, em primeiro momento, você precisa somente de ter um projeto, segue abaixo os requisitos para iniciar o projeto:

Java 17
Spring Boot 3.x.x
PosgtreSQL ou outro banco de dados
Postman
Importante: para que seu projeto rode certinho, é importante utilizar a versão 17 do Java e versão 3.x.x do Spring Boot, caso contrario você pode enfrentar um erro como esse: erro Spring Boot.

Repositório do projeto no GitHub: guilhermeJWT/security-jwt.

Resultado final ao longo deste tutorial
Ao longo deste tutorial passo a passo, você vai conseguir gerar o Token JWT com uma autenticação bem completa, veja o resultado final:

jwt com spring security na prática
Dica: se você estiver utilizando a versão 17 do Java e a versão 3.x.x superior do Spring Boot, basta COPIA e COLAR que vai dar tudo certo =).

Configuração do Projeto
Adicione as seguintes dependências no arquivo pom.xml:

XML
1
        <dependency>
2
            <groupId>org.springframework.boot</groupId>
3
            <artifactId>spring-boot-starter-data-jpa</artifactId>
4
        </dependency>
5
6
        <dependency>
7
            <groupId>org.postgresql</groupId>
8
            <artifactId>postgresql</artifactId>
9
            <scope>runtime</scope>
10
        </dependency>
11
12
        <dependency>
13
            <groupId>org.springframework.boot</groupId>
14
            <artifactId>spring-boot-starter-security</artifactId>
15
        </dependency>
16
17
        <dependency>
18
            <groupId>com.auth0</groupId>
19
            <artifactId>java-jwt</artifactId>
20
            <version>4.4.0</version>
21
        </dependency>
22
23
        <dependency>
24
            <groupId>org.springframework.boot</groupId>
25
            <artifactId>spring-boot-starter-web</artifactId>
26
        </dependency>
27
28
        <dependency>
29
            <groupId>org.projectlombok</groupId>
30
            <artifactId>lombok</artifactId>
31
            <optional>true</optional>
32
        </dependency>
33
34
        <dependency>
35
            <groupId>org.springframework.boot</groupId>
36
            <artifactId>spring-boot-starter</artifactId>
37
        </dependency>
Logo após adicionar as dependências, você precisa configurar sua conexão com o Banco de Dados, em nosso projeto vamos utilizar o PostgreSQL na versão 12, mais você pode utilizar qualquer outro banco da sua preferência.

Abaixo as configurações de conexão:

Properties
1
spring.application.name=security-jwt
2
spring.datasource.url=jdbc:postgresql://localhost:5432/jwtsecurity
3
spring.datasource.username=postgres
4
spring.datasource.password=postgres
5
spring.datasource.driver-class-name=org.postgresql.Driver
6
spring.jpa.hibernate.ddl-auto=update
Se você estiver utilizando o Docker, você pode seguir esse passo a passo de como subir uma: imagem do Postgres.

Estrutura de Pacotes do Projeto
Nosso projeto irá seguir está estrutura de pacotes, mais você pode separar as classes da forma que você achar mais produtiva de entender, segue abaixo nossa estrutura:


No pacote MODEL, adicione as seguintes classes: ModelUser, ModelRole, ModelUserDetailsImpl.

Essas classes serão importantes para as configurações de autenticação de usuários que vamos fazer ao longo do tutorial, de primeiro momento já deixe elas prontas para uso:

Classe: ModelUser
Java
1
package br.com.virandoprogramador.security_jwt.model;
2
3
import jakarta.persistence.*;
4
import lombok.AllArgsConstructor;
5
import lombok.Builder;
6
import lombok.Data;
7
import lombok.NoArgsConstructor;
8
9
import java.io.Serializable;
10
import java.util.List;
11
12
@AllArgsConstructor
13
@NoArgsConstructor
14
@Builder
15
@Data
16
@Table(name = "modeluser")
17
@Entity
18
public class ModelUser implements Serializable {
19
20
    @Id
21
    @GeneratedValue(strategy = GenerationType.AUTO)
22
    private Long id;
23
24
    private String email;
25
26
    private String password;
27
28
    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.PERSIST)
29
    @JoinTable(name="users_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name="role_id"))
30
    private List<ModelRole> roles;
31
  
32
}
Classe: ModelRole
Java
1
package br.com.virandoprogramador.security_jwt.model;
2
3
import br.com.virandoprogramador.security_jwt.enums.Role;
4
import jakarta.persistence.*;
5
import lombok.*;
6
7
8
@Builder
9
@NoArgsConstructor
10
@AllArgsConstructor
11
@Data
12
@Entity
13
@Table(name="roles")
14
public class ModelRole {
15
16
    @Id
17
    @GeneratedValue(strategy = GenerationType.AUTO)
18
    private Long id;
19
20
    @Enumerated(EnumType.STRING)
21
    private Role name;
22
23
}
Classe: ModelUserDetailsImpl
Java
1
package br.com.virandoprogramador.security_jwt.model;
2
3
import lombok.Getter;
4
import org.springframework.security.core.GrantedAuthority;
5
import org.springframework.security.core.authority.SimpleGrantedAuthority;
6
import org.springframework.security.core.userdetails.UserDetails;
7
8
import java.util.Collection;
9
import java.util.stream.Collectors;
10
11
@Getter
12
public class ModelUserDetailsImpl implements UserDetails {
13
14
    private ModelUser modelUser;
15
16
    public ModelUserDetailsImpl(ModelUser modelUser) {
17
        this.modelUser = modelUser;
18
    }
19
20
    @Override
21
    public Collection<? extends GrantedAuthority> getAuthorities() {
22
        return modelUser.getRoles()
23
                .stream()
24
                .map(role -> new SimpleGrantedAuthority(
25
                        role.getName().name()))
26
                .collect(Collectors.toList());
27
    }
28
29
    @Override
30
    public String getPassword() {
31
        return modelUser.getPassword();
32
    }
33
34
    @Override
35
    public String getUsername() {
36
        return modelUser.getEmail();
37
    }
38
39
    @Override
40
    public boolean isAccountNonExpired() {
41
        return true;
42
    }
43
44
    @Override
45
    public boolean isAccountNonLocked() {
46
        return true;
47
    }
48
49
    @Override
50
    public boolean isCredentialsNonExpired() {
51
        return true;
52
    }
53
54
    @Override
55
    public boolean isEnabled() {
56
        return true;
57
    }
58
59
}
No pacote ENUMS, adicione o seguinte Enum para definir as Roles dos Usuários:

Enum: Role
Java
1
package br.com.virandoprogramador.security_jwt.enums;
2
3
public enum Role {
4
    ROLE_USER,
5
    ROLE_ADMIN,
6
    ROLE_GERENTE,
7
    ROLE_VENDEDOR
8
}
No pacote DTO, Precisamos criar 4 classes(Record) que serão utilizados para usar na Api, este tipo de classe foi introduzido no Java 14, mais você pode utilizar uma classe normalmente.

Segue abaixo as classes: CreateUserDTO, JwtTokenDTO, LoginUserDTO, UserDTO.

Record: CreateUserDTO
Java
1
package br.com.virandoprogramador.security_jwt.dto;
2
3
import br.com.virandoprogramador.security_jwt.enums.Role;
4
5
public record CreateUserDTO(String email, String password, Role role) {
6
  
7
}
Record: JwtTokenDTO
Java
1
package br.com.virandoprogramador.security_jwt.dto;
2
3
public record JwtTokenDTO(String token) {
4
  
5
}
Record: LoginUserDTO
Java
1
package br.com.virandoprogramador.security_jwt.dto;
2
3
public record LoginUserDTO(String email, String password) {
4
  
5
}
Record: UserDTO
Java
1
package br.com.virandoprogramador.security_jwt.dto;
2
3
import br.com.virandoprogramador.security_jwt.enums.Role;
4
5
import java.util.List;
6
7
public record UserDTO(Long id, String email, List<Role> roles) {
8
  
9
}
No pacote REPOSITORY, adicione a seguinte interface para que seja possível utilizar os métodos do Spring Data Jpa, a interface será utilizada para algumas funções ao longo do tutorial.

Interface: UserRepository
Java
1
package br.com.virandoprogramador.security_jwt.repository;
2
3
import br.com.virandoprogramador.security_jwt.model.ModelUser;
4
import org.springframework.data.jpa.repository.JpaRepository;
5
import org.springframework.stereotype.Repository;
6
7
import java.util.Optional;
8
9
@Repository
10
public interface UserRepository extends JpaRepository<ModelUser, Long> {
11
12
    Optional<ModelUser> findByEmail(String email);
13
14
}
Na camada de repository, temos o método findByEmail, que recebe o e-mail de um usuário, ele é utilizado para pesquisar no Banco de Dados se existe algum Usuário com este e-mail, com isso podemos buscar suas credenciais, e autenticar na aplicação.

Camada de Segurança com Spring Security e Token JWT
Agora vamos começar o processo de adicionar segurança em nossa Api, nos pacotes SECURITY e SERVICE, são separadas as classes de configuração, nesta etapa você deve ter bastante atenção para que as configurações sejam aplicadas corretamente.

Importante: se você estiver copiando e colando os códigos, certamente você vai se deparar com algum erro por falta de classes, continue o tutorial para que os erros desapareçam.

Estrutura das Classes
No pacote SECURITY, vamos criar 2 classes, SecurityConfig e UserAuthenticationFilter, elas serão responsáveis para configurar a camada de segurança e autenticação do usuário.

Classe: SecurityConfig
Java
1
package br.com.virandoprogramador.security_jwt.security;
2
3
import org.springframework.beans.factory.annotation.Autowired;
4
import org.springframework.context.annotation.Bean;
5
import org.springframework.context.annotation.Configuration;
6
import org.springframework.security.authentication.AuthenticationManager;
7
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
8
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
9
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
10
import org.springframework.security.config.http.SessionCreationPolicy;
11
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
12
import org.springframework.security.crypto.password.PasswordEncoder;
13
import org.springframework.security.web.SecurityFilterChain;
14
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
15
16
@Configuration
17
@EnableWebSecurity
18
public class SecurityConfig {
19
20
    @Autowired
21
    private UserAuthenticationFilter userAuthenticationFilter;
22
23
    @Bean
24
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
25
        return httpSecurity.csrf().disable()
26
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
27
                .and().authorizeHttpRequests()
28
                .requestMatchers("api/users/**").permitAll()
29
                .anyRequest().denyAll()
30
                .and().
31
                    addFilterBefore(userAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
32
                .build();
33
    }
34
35
    @Bean
36
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
37
        return authenticationConfiguration.getAuthenticationManager();
38
    }
39
40
    @Bean
41
    public PasswordEncoder passwordEncoder() {
42
        return new BCryptPasswordEncoder();
43
    }
44
}
A classe SecurityConfig é responsável por configurar como deve funcionar a segurança, é a principal configuração para definir quais rotas serão acessadas ou autenticadas, a anotação @EnableWebSecurity habilita a configuração de segurança para a aplicação.

Automaticamente, o Spring Boot entende que essa classe será adicionada métodos como authenticationManager e securityFilterChain.

Observação: note que na linha 28, estamos permitindo o acesso para a seguinte rota: “api/users”, essa rota será utilizada para realizar a autenticação de usuário e criação de um novo usuário na Api, vamos utilizar elas daqui a pouco para testar a aplicação.

Outro ponto importante, essa rota deve ser liberada para todos que tiverem acesso na Api, por isso definimos a configuração .permitAll(), pense comigo, como vamos acessar uma tela de login se não temos autorização pra isso? por esse motivo, devem ser liberadas.

Classe: UserAuthenticationFilter
Java
1
package br.com.virandoprogramador.security_jwt.security;
2
3
import br.com.virandoprogramador.security_jwt.model.ModelUser;
4
import br.com.virandoprogramador.security_jwt.model.ModelUserDetailsImpl;
5
import br.com.virandoprogramador.security_jwt.repository.UserRepository;
6
import br.com.virandoprogramador.security_jwt.service.JwtTokenService;
7
import jakarta.servlet.FilterChain;
8
import jakarta.servlet.ServletException;
9
import jakarta.servlet.http.HttpServletRequest;
10
import jakarta.servlet.http.HttpServletResponse;
11
import org.springframework.beans.factory.annotation.Autowired;
12
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
13
import org.springframework.security.core.Authentication;
14
import org.springframework.security.core.context.SecurityContextHolder;
15
import org.springframework.stereotype.Component;
16
import org.springframework.web.filter.OncePerRequestFilter;
17
18
import java.io.IOException;
19
import java.util.Arrays;
20
21
@Component
22
public class UserAuthenticationFilter extends OncePerRequestFilter{
23
24
    @Autowired
25
    private JwtTokenService jwtTokenService;
26
27
    @Autowired
28
    private UserRepository userRepository;
29
30
    @Override
31
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
32
        if (verificaEndpointsPublicos(request)) {
33
            String token = recuperaToken(request);
34
            if (token != null) {
35
                String subject = jwtTokenService.getSubjectFromToken(token);
36
                ModelUser modelUser = userRepository.findByEmail(subject).get();
37
                ModelUserDetailsImpl modelUserDetails = new ModelUserDetailsImpl(modelUser);
38
                Authentication authentication =
39
                        new UsernamePasswordAuthenticationToken(
40
                                modelUserDetails.getUsername(),
41
                                null,
42
                                modelUserDetails.getAuthorities());
43
44
                SecurityContextHolder.getContext().setAuthentication(authentication);
45
            } else {
46
                throw new RuntimeException("Token inexistente!");
47
            }
48
        }
49
        filterChain.doFilter(request, response);
50
    }
51
52
    private boolean verificaEndpointsPublicos(HttpServletRequest request) {
53
        String requestURI = request.getRequestURI();
54
        return !Arrays.asList("/api/users/login", "/api/users").contains(requestURI);
55
    }
56
57
    private String recuperaToken(HttpServletRequest request) {
58
        String authorizationHeader = request.getHeader("Authorization");
59
        if (authorizationHeader != null) {
60
            return authorizationHeader.replace("Bearer ", "");
61
        }
62
        return null;
63
    }
64
65
}
Importante: ao adicionar essa classe ao projeto, você irá se deparar com o erro da falta da classe JwtTokenService, essa classe vamos criar no próximo passo.

No pacote SERVICE, vamos precisar criar 3 classes: JwtTokenService, UserDetailServiceImpl e UserService.

Essa camada da aplicação, ficará responsável pela regra de negócio das autenticações, como geração do Token JWT, autenticar o Usuário entre outras.

Classe: JwtTokenService
Java
1
package br.com.virandoprogramador.security_jwt.service;
2
3
import br.com.virandoprogramador.security_jwt.model.ModelUserDetailsImpl;
4
import com.auth0.jwt.JWT;
5
import com.auth0.jwt.algorithms.Algorithm;
6
import com.auth0.jwt.exceptions.JWTCreationException;
7
import com.auth0.jwt.exceptions.JWTVerificationException;
8
import org.springframework.beans.factory.annotation.Value;
9
import org.springframework.stereotype.Service;
10
11
import java.time.Instant;
12
import java.time.ZoneId;
13
import java.time.ZonedDateTime;
14
15
@Service
16
public class JwtTokenService {
17
18
    @Value("${token.jwt.secret.key}")
19
    private String secret_Key;
20
21
    @Value("${token.jwt.issuer}")
22
    private String issuer;
23
24
    public String generateToken(ModelUserDetailsImpl user) {
25
        try {
26
            Algorithm algorithm = Algorithm.HMAC256(secret_Key);
27
            return JWT.create()
28
                    .withIssuer(issuer)
29
                    .withIssuedAt(dataCriacao())
30
                    .withExpiresAt(dataExpiracao())
31
                    .withSubject(user.getUsername())
32
                    .sign(algorithm);
33
        } catch (JWTCreationException exception){
34
            throw new JWTCreationException("Erro ao gerar o token: ", exception);
35
        }
36
    }
37
38
    public String pegarToken(String token) {
39
        try {
40
            Algorithm algorithm = Algorithm.HMAC256(secret_Key);
41
            return JWT.require(algorithm)
42
                    .withIssuer(issuer)
43
                    .build()
44
                    .verify(token)
45
                    .getSubject();
46
        } catch (JWTVerificationException exception){
47
            throw new JWTVerificationException("Token inválido ou expirado!");
48
        }
49
    }
50
51
    private Instant dataExpiracao() {
52
        return ZonedDateTime.now(ZoneId.of("America/Sao_Paulo"))
53
                .plusHours(2).toInstant();
54
    }
55
56
    private Instant dataCriacao() {
57
        return ZonedDateTime.now(ZoneId.of("America/Sao_Paulo")).toInstant();
58
    }
59
60
}
Nesta classe, estamos realizando a geração do token pegando os valores de secret_Key, issuer, dataCriacao, dataExpiracao e username do Usuário.

No método abaixo, estamos realizando a leitura deste token para validação.

Observação: note que na linha 18 e 21 estamos definindo 2 valores para as variáveis secret_Key e issuer, vamos precisar dessas configurações para definir uma chave secreta, segue abaixo os valores das variáveis no arquivo application.properties.

Properties
1
token.jwt.secret.key=virandoprogramador-secret-key
2
token.jwt.issuer=virandoprogramador-exemple-issuer
Classe: UserDetailsService
Java
1
package br.com.virandoprogramador.security_jwt.service;
2
3
import br.com.virandoprogramador.security_jwt.model.ModelUser;
4
import br.com.virandoprogramador.security_jwt.model.ModelUserDetailsImpl;
5
import br.com.virandoprogramador.security_jwt.repository.UserRepository;
6
import org.springframework.beans.factory.annotation.Autowired;
7
import org.springframework.security.core.userdetails.UserDetails;
8
import org.springframework.security.core.userdetails.UserDetailsService;
9
import org.springframework.security.core.userdetails.UsernameNotFoundException;
10
import org.springframework.stereotype.Service;
11
12
@Service
13
public class UserDetailsServiceImpl implements UserDetailsService {
14
15
    @Autowired
16
    private UserRepository userRepository;
17
18
    @Override
19
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
20
        ModelUser modelUser = userRepository.findByEmail(username)
21
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado!"));
22
        return new ModelUserDetailsImpl(modelUser);
23
    }
24
}
Nesta classe, temos um único método que é carregar um Usuário pelo username(e-mail), vamos precisar deste método para realizar a verificação do Usuário posteriormente.

Classe: UserService
Java
1
package br.com.virandoprogramador.security_jwt.service;
2
3
import br.com.virandoprogramador.security_jwt.dto.CreateUserDTO;
4
import br.com.virandoprogramador.security_jwt.dto.JwtTokenDTO;
5
import br.com.virandoprogramador.security_jwt.dto.LoginUserDTO;
6
import br.com.virandoprogramador.security_jwt.model.ModelRole;
7
import br.com.virandoprogramador.security_jwt.model.ModelUser;
8
import br.com.virandoprogramador.security_jwt.model.ModelUserDetailsImpl;
9
import br.com.virandoprogramador.security_jwt.repository.UserRepository;
10
import br.com.virandoprogramador.security_jwt.security.SecurityConfig;
11
import org.springframework.beans.factory.annotation.Autowired;
12
import org.springframework.security.authentication.AuthenticationManager;
13
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
14
import org.springframework.security.core.Authentication;
15
import org.springframework.stereotype.Service;
16
17
import java.util.List;
18
19
@Service
20
public class UserService {
21
22
    @Autowired
23
    private UserRepository userRepository;
24
25
    @Autowired
26
    private SecurityConfig securityConfig;
27
28
    @Autowired
29
    private AuthenticationManager authenticationManager;
30
31
    @Autowired
32
    private JwtTokenService jwtTokenService;
33
34
    public void salvarUsuario(CreateUserDTO createUserDto) {
35
        ModelUser newUser = ModelUser.builder()
36
                .email(createUserDto.email())
37
                .password(securityConfig.passwordEncoder().encode(createUserDto.password()))
38
                .roles(List.of(ModelRole.builder().name(createUserDto.role()).build()))
39
                .build();
40
41
        userRepository.save(newUser);
42
    }
43
44
    public JwtTokenDTO autenticarUsuario(LoginUserDTO loginUserDto) {
45
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
46
                new UsernamePasswordAuthenticationToken(loginUserDto.email(), loginUserDto.password());
47
48
        Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
49
        ModelUserDetailsImpl modelUserDetails = (ModelUserDetailsImpl) authentication.getPrincipal();
50
        return new JwtTokenDTO(jwtTokenService.generateToken(modelUserDetails));
51
    }
52
}
Nesta classe, temos 2 métodos para salvar um novo Usuário e autenticar um Usuário existente, também será muito importante nos próximos passos.

Testando a Api com Spring Security e JWT
Estamos chegando no final, mais antes precisamos criar uma camada de Controller, onde ficará nossos endpoits para testar a criação e validação de segurança.

No pacote CONTROLLER, crie a seguinte classe: UserController, ela terá basicamente 2 métodos, loginUsuario e salvarUsuario.

Classe: UserController
Java
1
package br.com.virandoprogramador.security_jwt.controller;
2
3
import br.com.virandoprogramador.security_jwt.dto.CreateUserDTO;
4
import br.com.virandoprogramador.security_jwt.dto.JwtTokenDTO;
5
import br.com.virandoprogramador.security_jwt.dto.LoginUserDTO;
6
import br.com.virandoprogramador.security_jwt.service.UserService;
7
import org.springframework.beans.factory.annotation.Autowired;
8
import org.springframework.http.HttpStatus;
9
import org.springframework.http.ResponseEntity;
10
import org.springframework.web.bind.annotation.*;
11
12
@RestController
13
@RequestMapping("/api/users")
14
public class UserController {
15
16
    @Autowired
17
    private UserService userService;
18
19
    @PostMapping("/login")
20
    public ResponseEntity<JwtTokenDTO> loginUsuario(@RequestBody LoginUserDTO loginUserDto) {
21
        JwtTokenDTO token = userService.autenticarUsuario(loginUserDto);
22
        return new ResponseEntity<>(token, HttpStatus.OK);
23
    }
24
25
    @PostMapping
26
    public ResponseEntity<Void> salvarUsuario(@RequestBody CreateUserDTO createUserDto) {
27
        userService.salvarUsuario(createUserDto);
28
        return new ResponseEntity<>(HttpStatus.CREATED);
29
    }
30
}
Para testar nossa aplicação, precisamos entender as rotas, observe que nossa api começa com /api/users, agora é só testar, no meu caso estou utilizado o projeto local, então minha rota( e possivelmente a sua ) deve ser:

localhost:8080/api/users/login e localhost:8080/api/users.

Agora precisamos testar, para isso você vai precisar de algum Software de teste de Api, como Postman e Insomnia.

Criando um novo Usuário
Para criar um novo Usuário, acesse a seguinte rota: localhost:8080/api/users com o método POST, no campo body do Postman, vá em raw e em seguida selecione JSON:

token jwt com spring security
Opa! criamos um novo Usuário no banco de dados, observe o status 201 Created, que significa que a requisição deu certo e que foi criado um registro no servidor.

A classe que recebe os dados de um novo Usuário é a CreateUserDTO, recebendo o email, password e a role.

Bora ver o user salvo no Postgres? acesse seu banco de dados e vá na tabela modeluser.

spring security jwt
Observação: note que o password está criptografado no banco de dados, para que isso seja possível, utilizamos a classe BCryptPasswordEncoder para criptografar a senha e salvar no banco de dados. Desta forma, conseguimos garantir que se nosso banco de dados for hackeado, o atacante não conseguira identificar a senha real, precisaria de um algoritimo hash, que somente nossa aplicação consegue entender.

Autenticando o Usuário na Api com o Token JWT
Como você viu no começo do artigo, vamos autenticar na aplicação, utilizando as credenciais que acabamos de criar.

Para autenticar na api acesse: localhost:8080/api/users/login, método POST com email e password que você cadastrou.

jwt spring boot
Prontinho, veja que no corpo da requisição retornou código 200 OK, que significa que a requisição deu tudo certo, a validação de Usuário, retornando o Token.

Para testar as outras rotas da sua aplicação, você precisa pegar o Token e adicionar no campo Authorization -> Bearer Token -> Inserir o Token.

Considerações finais
Em resumo, neste artigo, fornecemos um guia passo a passo detalhado sobre como implementar JSON Web Token (JWT) com Spring Boot. Desde a configuração inicial até a integração com a autenticação de usuário, nosso objetivo foi oferecer uma compreensão abrangente de como esse processo funciona.

Ao longo do artigo, você conheceu os fundamentos do JWT e como ele pode ser utilizado para garantir a segurança das nossas aplicações. Demonstramos como configurar o Spring Security para lidar com a autenticação de usuários de forma eficiente, proporcionando uma base sólida para a construção de sistemas robustos.

Além disso, criamos uma aplicação de exemplo completa, demonstrando na prática como todas essas peças se encaixam. Com isso, os leitores podem não apenas compreender os conceitos teóricos, mas também aplicá-los em projetos reais.

Portanto, encorajamos você a utilizar este projeto como ponto de partida em suas próprias aplicações. A implementação de JWT com Spring Boot não apenas fortalecerá a segurança do seu sistema, mas também proporcionará uma experiência de usuário mais segura.

Esperamos que este artigo tenha sido útil e que você possa aproveitar ao máximo os conhecimentos adquiridos aqui. Compartilhe nos grupos para ajudar mais Desenvolvedores Java. Obrigado por ler!

Perguntas Frequentes sobre Token JWT
Abaixo, irei responder algumas dúvidas bem comuns em relação ao Token JWT:

O que um token JWT faz?
Basicamente, um token JWT funciona como um mecanismo de autenticação e autorização, permitindo que um usuário prove sua identidade e acesse recursos de forma segura em um sistema distribuído. Ao transmitir informações em formato JSON, o token JWT codifica dados relevantes, como informações de usuário e metadados adicionais, de maneira compacta e segura.

Esses tokens são frequentemente utilizados em cenários onde a comunicação entre diferentes partes precisa ser segura e confiável, como em aplicações web, APIs e microsserviços.

Ao utilizar algoritmos de criptografia robustos, um token JWT pode garantir a integridade e a confidencialidade das informações transmitidas, tornando-o uma escolha popular para implementações de segurança em ambientes distribuídos.

Qual é a diferença entre JWT e Token normal?
A diferença entre JWT (JSON Web Token) e um token normal reside principalmente em onde e como são armazenados e utilizados. Um token normal, em geral, é armazenado no lado do servidor e é utilizado para autenticar solicitações subsequentes do mesmo usuário.

Por outro lado, a autenticação do lado do cliente usando JWT envolve a emissão de um token assinado para o cliente após o login bem-sucedido, que é então armazenado no lado do cliente e enviado de volta ao servidor com cada solicitação subsequente.

Em um sistema com token normal, quando um usuário faz login, o servidor autentica suas credenciais e, em seguida, gera um token que é associado à sessão do usuário no servidor. Esse token é então armazenado no lado do servidor e enviado de volta ao cliente, geralmente como um cookie HTTP. Com cada solicitação subsequente, o token é enviado de volta ao servidor para autenticar o usuário.

Por outro lado, com JWT, após o login bem-sucedido, o servidor emite um token JWT assinado para o cliente, contendo informações de autenticação e autorização. Esse token é então armazenado no lado do cliente, geralmente em local storage ou em um cookie seguro.

Com cada solicitação subsequente, o cliente envia o token JWT de volta ao servidor no cabeçalho da requisição. O servidor pode então validar a autenticidade e a integridade do token JWT sem a necessidade de consultar o armazenamento de sessão no servidor.

Os Tokens JWT são seguros?
Um dos pontos-chave a se considerar é que os tokens JWT contêm uma assinatura criptográfica, o que pode dar a impressão de que são bastante seguros. No entanto, a presença de uma assinatura não é uma garantia absoluta de segurança. Assim como qualquer outra tecnologia de segurança, os tokens JWT são tão seguros quanto a implementação em que são utilizados.

Além disso, a segurança dos tokens JWT também depende da maneira como são gerenciados e protegidos durante todo o seu ciclo de vida. Por exemplo, se um token for armazenado de forma inadequada no lado do cliente, como em um local storage vulnerável a ataques de cross-site scripting (XSS), isso pode comprometer a segurança do sistema.

Outro aspecto é a validação adequada dos tokens JWT pelo servidor. Sem uma validação adequada, os tokens JWT podem ser suscetíveis a ataques de falsificação, manipulação ou replay.

Como saber se um Token é um JWT?
Para determinar se um token é um JSON Web Token (JWT), pode-se observar sua estrutura. Um JWT é composto por três seções distintas, cada uma separada por um ponto (.). Essas seções são:

Header (Cabeçalho): A primeira parte do JWT é o cabeçalho, que contém informações sobre o tipo de token e o algoritmo de assinatura utilizado. Este cabeçalho é representado em formato JSON.
Payload (Carga Útil): A segunda parte é a carga útil, que contém os dados reivindicados (claims) do token, como informações de usuário ou autorização. Assim como o cabeçalho, a carga útil também é codificada em JSON.
Signature (Assinatura): A terceira e última parte do JWT é a assinatura, que é gerada com base no cabeçalho, na carga útil e em uma chave secreta. Essa assinatura é usada para verificar a integridade do token e garantir que ele não tenha sido alterado.