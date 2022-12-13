package io.security.corespringsecurity.service.Impl;

import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.repository.UserRepository;
import io.security.corespringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service("userService")
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    @Override
    public void createUser(Account account) {
        userRepository.save(account);
    }
}
