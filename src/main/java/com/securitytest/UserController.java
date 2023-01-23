package com.securitytest;

import com.securitytest.entity.User;
import com.securitytest.security.auth.UserDetailsCustom;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("api/v1")
@RequiredArgsConstructor
public class UserController {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

//    private final JwtTokenProvider jwtTokenProvider;


    // 모든 사람이 접근 가능
    @GetMapping("home")
    public String home() {
        return "<h1>home</h1>";
    }

    // Tip : JWT를 사용하면 UserDetailsService를 호출하지 않기 때문에 @AuthenticationPrincipal 사용 불가능.
    // 왜냐하면 @AuthenticationPrincipal은 UserDetailsService에서 리턴될 때 만들어지기 때문이다.

    // 유저 혹은 매니저 혹은 어드민이 접근 가능
    @GetMapping("user")
    public String user(Authentication authentication) {
        UserDetailsCustom principal = (UserDetailsCustom) authentication.getPrincipal();
        System.out.println("principal : " + principal.getUser().getUserId());
        System.out.println("principal : " + principal.getUser().getUsername());
        System.out.println("principal : " + principal.getUser().getPassword());
        return "<h1>user</h1>";
    }

    // 매니저 혹은 어드민이 접근 가능
    @GetMapping("manager/reports")
    public String reports() {
        return "<h1>reports</h1>";
    }

    // 어드민이 접근 가능
    @GetMapping("admin/users")
    public List<User> users() {
        return userRepository.findAll();
    }

    @PostMapping("join/{userId}")
    public String join(@PathVariable String userId, @RequestBody User user) {
        System.out.println(userId);
        System.out.println(user.toString());
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRole("ROLE_ADMIN");
        userRepository.save(user);
        return "회원가입완료";
    }

//    @PostMapping("login")
//    public String login(@RequestBody LoginRequestDto loginRequestDto) {
//        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
//                loginRequestDto.getUserId(), loginRequestDto.getPassword()
//        ));
//        return jwtTokenProvider.generateToken(authentication);
//    }
}
