## 前言
其实挺早就想写一篇关于jwt的博文去好好总结一下之前踩过的坑了，但是事情有点太多了，一直没抽出时间来写，刚好现在有点时间可以好好静下来写一遍(可能)有点质量的博文吧，毕竟一直都是看别人的博文去学习，我也好好写一遍吧哈哈。既然如果偶然搜到这篇文章的话，我相信大家应该都了解了什么是jwt，比较想知道怎么使用springboot+spring-security去实现，当然也可以使用shiro，其实道理都差不多， ~~可能看到标题可能会有疑问，为什么会有一个redis呢？这是我学习有关jwt相关知识的时候产生的一些问题，以及自己对这方面问题的一些解决方案，接下来的文章我会详细跟大家讨论一下的，欢迎大家也可以一起讨论一下。~~ （刚开始写博客，写的不好多多包涵）

看完这篇文章之后你可以知道

1. 如何使用springboot，springSecurity，jwt实现基于token的权限管理
2. 统一处理无权限请求的结果

## JWT
再稍微提一提jwt吧，在前段时间有个小项目是前后端分离的，所以需要用到基于token的权限管理机制，所以就了解到了jwt这一个方案。不过关于这个方案，似乎没有一个如何管理已经生产的token的方法（如果有的话欢迎告知，我还不知道呢。。）一旦生成了一个token，就无法对该token进行任何操作，无法使该token失效，只有等到该token到了过期的时间点才失效，这样就会有一个很大的隐患。然后搜索了挺多相关的资料以及经过相当长一段时间的思考决定使用redis去管理已经生成的token，下面会~~详细~~说一下。

## 整理一下思路
创建一个新工程时，我们需要思考一下我们接下来需要的一些步骤，需要做什么，怎么做。

 - 搭建springboot工程
 - 导入springSecurity跟jwt的依赖
 - 用户的实体类
 - dao层
 - service层（真正开发时再写，这里就直接调用dao层操作数据库）
 - 实现UserDetailsService接口
 - 实现UserDetails接口
 - 验证用户登录信息的拦截器
 - 验证用户权限的拦截器
 - springSecurity配置
 - 认证的Controller以及测试的controller
 - 测试
 - 享受成功的喜悦

## 创建一个springboot工程
建议使用maven去构建项目。
```
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
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <scope>runtime</scope>
        </dependency>
```


## 实体类User
创建一个演示的实体类User，包含最基本的用户名跟密码，至于role干嘛用后面会提到
```java
@Entity
@Table(name = "jd_user")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id;

    @Column(name = "username")
    private String username;

    @Column(name = "password")
    private String password;

    @Column(name = "role")
    private String role;

	// getter and setter...
}
```

## JWT工具类
这里jwt我选择的是[jjwt](https://github.com/jwtk/jjwt)，至于为什么，可能是因为我用的比较顺手吧_(:3」∠)_
```
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.0</version>
</dependency>
```

### JwtTokenUtils
jwt工具类，对jjwt封装一下方便调用

```java
public class JwtTokenUtils {

    public static final String TOKEN_HEADER = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer ";

    private static final String SECRET = "jwtsecretdemo";
    private static final String ISS = "echisan";

    // 过期时间是3600秒，既是1个小时
    private static final long EXPIRATION = 3600L;

    // 选择了记住我之后的过期时间为7天
    private static final long EXPIRATION_REMEMBER = 604800L;

    // 创建token
    public static String createToken(String username, boolean isRememberMe) {
        long expiration = isRememberMe ? EXPIRATION_REMEMBER : EXPIRATION;
        return Jwts.builder()
                .signWith(SignatureAlgorithm.HS512, SECRET)
                .setIssuer(ISS)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration * 1000))
                .compact();
    }

    // 从token中获取用户名
    public static String getUsername(String token){
        return getTokenBody(token).getSubject();
    }

    // 是否已过期
    public static boolean isExpiration(String token){
        return getTokenBody(token).getExpiration().before(new Date());
    }

    private static Claims getTokenBody(String token){
        return Jwts.parser()
                .setSigningKey(SECRET)
                .parseClaimsJws(token)
                .getBody();
    }
}
```

## UserRepository
写一个根据用户名获取用户的方法，后续会用到
```java
public interface UserRepository extends CrudRepository<User, Integer> {
    User findByUsername(String username);
}
```

## UserDetailsServiceImpl
使用springSecurity需要实现`UserDetailsService`接口供权限框架调用，该方法只需要实现一个方法就可以了，那就是根据用户名去获取用户，那就是上面repository定义的方法了，这里直接调用了。
```java
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(s);
        return new JwtUser(user);
    }

}
```

由于接口方法需要返回一个`UserDetails`类型的接口，所以这边就再写一个类去实现一下这个接口。
### JwtUser
实现这个接口需要实现几个方法
```java
public class JwtUser implements UserDetails {

    private Integer id;
    private String username;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;

    public JwtUser() {
    }

    // 写一个能直接使用user创建jwtUser的构造器
    public JwtUser(User user) {
        id = user.getId();
        username = user.getUsername();
        password = user.getPassword();
        authorities = Collections.singleton(new SimpleGrantedAuthority(user.getRole()));
    }

	// 获取权限信息，目前博主只会拿来存角色。。
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

	// 账号是否未过期，默认是false，记得要改一下
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

	// 账号是否未锁定，默认是false，记得也要改一下
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

	// 账号凭证是否未过期，默认是false，记得还要改一下
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

	// 这个有点抽象不会翻译，默认也是false，记得改一下
    @Override
    public boolean isEnabled() {
        return true;
    }

	// 我自己重写打印下信息看的
    @Override
    public String toString() {
        return "JwtUser{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", authorities=" + authorities +
                '}';
    }
}

```


## 配置拦截器
可以说到目前为止这是最复杂的一个步骤，其实搞清楚了还是挺简单的，网上挺多人都更倾向于使用shiro，但是偶尔也要尝试一下新东西的嘛，但是当时我在摸索的时候遇到挺多坑，当时也已经到了思考人生的地步了  ~~框架不是为了简化开发吗！为什么！明明jwt加上权限框架是双倍的快乐！为什么会这样！~~(╯°口°)╯(┴—┴

回到正题，到底要怎么配置呢？使用过shiro的人会知道，鉴权的话需要自己实现一个realm，重写两个方法，第一是用户验证，第二是鉴权。在spring-security中也不例外，这边需要实现两个过滤器。使用`JWTAuthenticationFilter`去进行用户账号的验证，使用`JWTAuthorizationFilter`去进行用户权限的验证。

### JWTAuthenticationFilter
`JWTAuthenticationFilter`继承于`UsernamePasswordAuthenticationFilter`
该拦截器用于获取用户登录的信息，只需创建一个`token`并调用`authenticationManager.authenticate()`让spring-security去进行验证就可以了，不用自己查数据库再对比密码了，这一步交给spring去操作。
这个操作有点像是shiro的`subject.login(new UsernamePasswordToken())`，验证的事情交给框架。
献上这一部分的代码。
```java
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {

        // 从输入流中获取到登录的信息
        try {
            LoginUser loginUser = new ObjectMapper().readValue(request.getInputStream(), LoginUser.class);
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginUser.getUsername(), loginUser.getPassword(), new ArrayList<>())
            );
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    // 成功验证后调用的方法
    // 如果验证成功，就生成token并返回
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

		// 查看源代码会发现调用getPrincipal()方法会返回一个实现了`UserDetails`接口的对象
		// 所以就是JwtUser啦
        JwtUser jwtUser = (JwtUser) authResult.getPrincipal();
        System.out.println("jwtUser:" + jwtUser.toString());
        String token = JwtTokenUtils.createToken(jwtUser.getUsername(), false);
        // 返回创建成功的token
        // 但是这里创建的token只是单纯的token
        // 按照jwt的规定，最后请求的格式应该是 `Bearer token`
        response.setHeader("token", JwtTokenUtils.TOKEN_PREFIX + token);
    }

	// 这是验证失败时候调用的方法
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.getWriter().write("authentication failed, reason: " + failed.getMessage());
    }
}
```

### JWTAuthorizationFilter
验证成功当然就是进行鉴权了，每一次需要权限的请求都需要检查该用户是否有该权限去操作该资源，当然这也是框架帮我们做的，那么我们需要做什么呢？很简单，只要告诉spring-security该用户是否已登录，是什么角色，拥有什么权限就可以了。
`JWTAuthenticationFilter`继承于`BasicAuthenticationFilter`，至于为什么要继承这个我也不太清楚了，这个我也是网上看到的其中一种实现，实在springSecurity苦手，不过我觉得不继承这个也没事呢（实现以下filter接口或者继承其他filter实现子类也可以吧）只要确保过滤器的顺序，`JWTAuthorizationFilter`在`JWTAuthenticationFilter`后面就没问题了。
```java
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {

        String tokenHeader = request.getHeader(JwtTokenUtils.TOKEN_HEADER);
        // 如果请求头中没有Authorization信息则直接放行了
        if (tokenHeader == null || !tokenHeader.startsWith(JwtTokenUtils.TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }
        // 如果请求头中有token，则进行解析，并且设置认证信息
        SecurityContextHolder.getContext().setAuthentication(getAuthentication(tokenHeader));
        super.doFilterInternal(request, response, chain);
    }

    // 这里从token中获取用户信息并新建一个token
    private UsernamePasswordAuthenticationToken getAuthentication(String tokenHeader) {
        String token = tokenHeader.replace(JwtTokenUtils.TOKEN_PREFIX, "");
        String username = JwtTokenUtils.getUsername(token);
        if (username != null){
            return new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
        }
        return null;
    }
}
```

## 配置SpringSecurity
到这里基本操作都写好啦，现在就需要我们将这些辛苦写好的“组件”组合到一起发挥作用了，那就需要配置了。需要开启一下注解`@EnableWebSecurity`然后再继承一下`WebSecurityConfigurerAdapter`就可以啦，springboot就是可以为所欲为~
```java
@EnableWebSecurity
// 至于为什么要配置这个，嘿嘿，卖个关子
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    // 因为UserDetailsService的实现类实在太多啦，这里设置一下我们要注入的实现类
    @Qualifier("userDetailsServiceImpl")
    private UserDetailsService userDetailsService;

	// 加密密码的，安全第一嘛~
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable()
                .authorizeRequests()
                // 测试用资源，需要验证了的用户才能访问
                .antMatchers("/tasks/**").authenticated()
                // 其他都放行了
                .anyRequest().permitAll()
                .and()
                .addFilter(new JWTAuthenticationFilter(authenticationManager()))
                .addFilter(new JWTAuthorizationFilter(authenticationManager()))
                // 不需要session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
        return source;
    }
}
```

## AuthController
连配置都搞定了，那么问题来了，没有账号密码呢。所以写一个注册的控制器，这个就不是难事啦
```java
@RestController
@RequestMapping("/auth")
public class AuthController {

	// 为了减少篇幅就不写service接口了
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @PostMapping("/register")
    public String registerUser(@RequestBody Map<String,String> registerUser){
        User user = new User();
        user.setUsername(registerUser.get("username"));
        // 记得注册的时候把密码加密一下
        user.setPassword(bCryptPasswordEncoder.encode(registerUser.get("password")));
        user.setRole("ROLE_USER");
        User save = userRepository.save(user);
        return save.toString();
    }
}
```
等等！注册是有了，那登录在哪呢？我们看一下`UsernamePasswordAuthenticationFilter`的源代码
```java
	public UsernamePasswordAuthenticationFilter() {
		super(new AntPathRequestMatcher("/login", "POST"));
	}
```
可以看出来默认是`/login`，所以登录直接使用这个路径就可以啦~当然也可以自定义
只需要在`JWTAuthenticationFilter`的构造方法中加入下面那一句话就可以啦
```java
 public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        super.setFilterProcessesUrl("/auth/login");
    }
```
所以现在认证的路径统一了一下也是挺好的~看起来相当舒服了
注册：`/auth/register`
登录：`/auth/login`

## TaskController
当然注册登录都完成了，那就是写一个测试控制器，一个需要权限的控制器去测试了，为了控制一下文章篇幅，写了一个比较简单的控制器作为演示
```java
@RestController
@RequestMapping("/tasks")
public class TaskController {

    @GetMapping
    public String listTasks(){
        return "任务列表";
    }
    
    @PostMapping
    public String newTasks(){
        return "创建了一个新的任务";
    }
    
    @PutMapping("/{taskId}")
    public String updateTasks(@PathVariable("taskId")Integer id){
        return "更新了一下id为:"+id+"的任务";
    }
    
    @DeleteMapping("/{taskId}")
    public String deleteTasks(@PathVariable("taskId")Integer id){
        return "删除了id为:"+id+"的任务";
    }
}
```

## 测试
到这里基本操作都做好了，可以去测试一下了，这里使用的是postman比较直观明了了。下面先注册一下账号，这里返回了插入了数据库之后的用户实体，所以注册是成功了

![注册](https://wx3.sinaimg.cn/large/7fa15162gy1fsqzegnzwxj20h4064aa6.jpg)
![注册成功](https://ws1.sinaimg.cn/large/7fa15162gy1fsqzeoso7vj20or02x0sp.jpg)

接下来先测试一下先不登录访问一下我们的tasks，这里理所当然403无权限访问了
![未登录403](https://ws3.sinaimg.cn/large/7fa15162gy1fsqzezp5fzj20dl0d2q3d.jpg)

然后终于能登录了，接下来尝试一下登录之后再次访问tasks看看是什么结果
![登录](https://ws1.sinaimg.cn/large/7fa15162gy1fsqzf7q1uwj20f406awel.jpg)
发送了登录请求之后查看响应头，能看到我们生成后的token，那就是登录成功了
![登录成功](https://wx4.sinaimg.cn/large/7fa15162gy1fsqzfdpjcuj214y0as3z0.jpg)
接下来只需要把该响应头添加到我们的请求头上去，这里需要把`Bearer[空格]`去掉，注意Bearer后的空格也要去掉，因为postman再选了BearerToken之后会自动在token前面再加一个Bearer
![设置请求头](https://ws2.sinaimg.cn/large/7fa15162gy1fsqzfrysllj21660aw750.jpg)
再次访问一下tasks，结果理想当然的是成功啦~
![成功请求](https://wx3.sinaimg.cn/large/7fa15162gy1fsqzg491b4j20uw08mwes.jpg)

## 初期总结
到这里我们一个基础的Springboot+SpringSecurity+Jwt已经搭建好了。
到这里一个基本的jwt已经实现了，但是总觉得哪里不对呢，写了这么多才只是登录成功了？权限管理呢？token管理呢？
确实，看一下上面的代码。在实现`UserDetails`接口的时候写了一些奇怪的东西，就是这个`getAuthorities`方法啦。
这是springSecurity用来获取用户权限的方法。
在User类中写得`role`在这里就能排上用场了，这里将要实现的权限管理是基于角色的权限管理，再细颗粒的博主就不会啦哈哈哈，但还是可以看一看的。
```java
    // 写一个能直接使用user创建jwtUser的构造器
    public JwtUser(User user) {
        id = user.getId();
        username = user.getUsername();
        password = user.getPassword();
        // 这里只存储了一个角色的名字
        authorities = Collections.singleton(new SimpleGrantedAuthority(user.getRole()));
    }

    // 获取权限信息
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }
```
在springSecurity里建议角色名称改成`ROLE_`统一前缀的角色，例如`ROLE_USER,ROLE_ADMIN,ROLE_XXX`，至于为什么，后面会提到的，先不急，这里先这样干着。

## 基于角色的权限管理
到底怎么基于角色的权限管理呢，这个只需要告诉权限框架该用户拥有什么角色就可以了。但是吧要怎么告诉框架我什么角色呢。我们理一下如何实现基于角色的权限管理的思路

1. 用户验证成功，根据用户名以及过期时间生成token
2. 权限验证，假如能从token中获取用户名就该token验证成功
3. 创建一个`UsernamePasswordAuthenticationToken`该token包含用户的角色信息，而不是一个空的`ArrayList`，查看一下源代码是有以下一个构造方法的。
```java
	public UsernamePasswordAuthenticationToken(Object principal, Object credentials,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		this.credentials = credentials;
		super.setAuthenticated(true); // must use super, as we override
	}
```

好了，接下来要怎么办呢，可以往上滚动一下，再看一眼`JWTAuthorizationFilter`中鉴权的逻辑

1. 检查请求头中是否存在`Authorization`，如果没有直接放，如果有就对token进行解析
2. 解析token，检查是否能从token中取出username，如果有就算成功了
3. 再根据该username创建一个`UsernamePasswordAuthenticationToken`对象就算成功了

可这发现根本就不关`role`什么事啊    ![沉思](https://ws4.sinaimg.cn/large/7fa15162gy1fsqzb0b0c7j203o044q2q.jpg)

```java
	User user = userRepository.findByUsername("username");
	String role = user.getRole();
```
![这里写图片描述](https://ws2.sinaimg.cn/large/7fa15162gy1fsqzb8duumj201b01bq2r.jpg) 这还不简单！这不就完事了嘛！

可这不现实啊，每一次请求都要查询一下数据库这种开销这么大的操作当然是不行的。
思考一下，为什么是使用jwt而不是一个简简单单的`UUID`作为token呢。
jwt是由三部分组成的：

1. 第一部分我们称它为头部（header)
2. 第二部分我们称其为载荷（payload)
3. 第三部分是签证（signature)

我们这里准备使用它的第二部分，使用payload去存储我们的用户角色信息，由于第一第二部分都是公开的，任何人都能知道里面的信息，不建议存储一些比较敏感的数据，但是存放角色信息还是没有问题的。

### 改造一下JwtTokenUtils

```java
    // 添加角色的key
    private static final String ROLE_CLAIMS = "rol";

	// 修改一下创建token的方法
    public static String createToken(String username, String role, boolean isRememberMe) {
        long expiration = isRememberMe ? EXPIRATION_REMEMBER : EXPIRATION;
        HashMap<String, Object> map = new HashMap<>();
        map.put(ROLE_CLAIMS, role);
        return Jwts.builder()
                .signWith(SignatureAlgorithm.HS512, SECRET)
                // 这里要早set一点，放到后面会覆盖别的字段
                .setClaims(map)
                .setIssuer(ISS)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration * 1000))
                .compact();
    }
	
```

### 修改JWTAuthenticationFilter

```java
    JwtUser jwtUser = (JwtUser) authResult.getPrincipal();
    boolean isRemember = rememberMe.get() == 1;

    String role = "";
    // 因为在JwtUser中存了权限信息，可以直接获取，由于只有一个角色就这么干了
    Collection<? extends GrantedAuthority> authorities = jwtUser.getAuthorities();
    for (GrantedAuthority authority : authorities){
        role = authority.getAuthority();
    }
    // 根据用户名，角色创建token
    String token = JwtTokenUtils.createToken(jwtUser.getUsername(), role, isRemember);
```

### 修改JWTAuthorizationFilter

```java
    // 这里从token中获取用户信息并新建一个token
    private UsernamePasswordAuthenticationToken getAuthentication(String tokenHeader) {
        String token = tokenHeader.replace(JwtTokenUtils.TOKEN_PREFIX, "");
        String username = JwtTokenUtils.getUsername(token);
        String role = JwtTokenUtils.getUserRole(token);
        if (username != null){
            return new UsernamePasswordAuthenticationToken(username, null, 
                    Collections.singleton(new SimpleGrantedAuthority(role))
            );
        }
        return null;
    }
```

到这里基本上修改已经完成了，接下来就可以测试一下了，再配置一下springSecurity
```java
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable()
                .authorizeRequests()
                // 测试用资源，需要验证了的用户才能访问
                .antMatchers("/tasks/**").authenticated()
                // 需要角色为ADMIN才能删除该资源
                .antMatchers(HttpMethod.DELETE, "/tasks/**").hasAuthority("ROLE_ADMIN")
                // 其他都放行了
                .anyRequest().permitAll()
                .and()
                .addFilter(new JWTAuthenticationFilter(authenticationManager()))
                .addFilter(new JWTAuthorizationFilter(authenticationManager()))
                // 不需要session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }
```

由于更新了token的生成方式，所以需要重新登录一下获取新的token

接下来可以测试了，继续使用postman对tasks资源进行删除，显然不行。
![测试删除tasks](https://ws1.sinaimg.cn/large/7fa15162gy1fsqzcued4xj20ee0eqwf0.jpg)
试试看获取该资源会怎么样，获取tasks资源是没有问题的。
![测试获取tasks](https://wx3.sinaimg.cn/large/7fa15162gy1fsqzg491b4j20uw08mwes.jpg)

**接下来重头戏来了**
先在数据库里手动将admin的角色改成`ROLE_ADMIN` 修改完之后再登录一下获取新的token，再去尝试一下删除tasks资源
啪啪啪 成功啦~
![删除成功](https://user-images.githubusercontent.com/38010908/89498932-bc08b980-d7f1-11ea-92f6-273f356674ba.png)

到这里位置，基于角色的权限管理基本操作都做了一遍了，现在来解答一下上面挖的一些坑

1. 为什么要以`ROLE_`作为前缀
2. springSecurity中配置的注解`@EnableGlobalMethodSecurity(prePostEnabled = true)`是干嘛用的

第一个问题：
我们在springSecurity中配置了这样一句，意思是只有角色为`ROLE_ADMIN`才有权限删除该资源
`.antMatchers(HttpMethod.DELETE, "/tasks/**").hasAuthority("ROLE_ADMIN")`
假如我们使用了`ROLE_`作为前缀就能这样写了~是不是很方便呢哈哈
`.antMatchers(HttpMethod.DELETE, "/tasks/**").hasRole("ADMIN")`

第二个问题：
除了在springSecurity中配置访问权限，还有这种方式啦，也是十分的方便呢。但是如果要使用这用的方式就需要配置上那个注解啦，不然虽然写了下面的注解但是是不会生效的。
```java
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public String newTasks(){
        return "创建了一个新的任务";
    }
```

## 统一结果处理

当然会有一些需求是要统一处理被403响应的事件，很简单，只要新建一个类`JWTAuthenticationEntryPoint`实现一下接口`AuthenticationEntryPoint`就可以了
```java
public class JWTAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {

        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json; charset=utf-8");
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        String reason = "统一处理，原因："+authException.getMessage();
        response.getWriter().write(new ObjectMapper().writeValueAsString(reason));
    }
}
```

再配置一下springSecurity
```java
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable()
                .authorizeRequests()
                // 测试用资源，需要验证了的用户才能访问
                .antMatchers("/tasks/**").authenticated()
                .antMatchers(HttpMethod.DELETE, "/tasks/**").hasRole("ADMIN")
                // 其他都放行了
                .anyRequest().permitAll()
                .and()
                .addFilter(new JWTAuthenticationFilter(authenticationManager()))
                .addFilter(new JWTAuthorizationFilter(authenticationManager()))
                // 不需要session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // 加一句这个
                .exceptionHandling().authenticationEntryPoint(new JWTAuthenticationEntryPoint());
    }
```
这是统一处理后的结果
![这里写图片描述](https://wx4.sinaimg.cn/large/7fa15162gy1fsqzhbrakxj216v04aglo.jpg)

## 享受成功的喜悦
到这里一个较为完善的权限管理已经实现啦，如果哪里有不足或者出现错误可以告诉一下我，或者可以到GitHub上提个issue一起讨论下。

## 代码地址
Github: [springboot-jwt-demo](https://github.com/echisan/springboot-jwt-demo)
代码里也有挺多的注释，可以看一看，如果觉得这篇文章帮助到你了可以到github点个小星星鼓励一下博主~

## 结语
至于为什么没有redis，没有token管理，因为在我写这篇文章的时候想了很多，感觉我现在的解决方案也不是特别好，如果想知道的话可以到GitHub上找我，一起讨论下。
