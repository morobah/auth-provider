package org.login.service;

import org.login.persistence.dao.UserDAO;
import org.login.persistence.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service("customUserDetailsService")
@Transactional
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private UserDAO userDAO;

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userDAO.getUserByUsername(username);
        if (user == null) {
            return new org.springframework.security.core.userdetails.User(
                    ""
                    , ""
                    , false
                    , true
                    , true
                    , true
                    , getGrantedAuthorities(Arrays.asList("DUMMY_ROLE"))
            );
        }
        List<String> authorities = userDAO.getAuthorities(user.getUserId());
        return new org.springframework.security.core.userdetails.User(
                user.getUsername()
                , user.getPassword()
                , user.isEnabled()
                , true
                , true
                ,true
                , getGrantedAuthorities(authorities)
        );
    }

    private List<GrantedAuthority> getGrantedAuthorities(List<String> privileges) {
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        for (String privilege : privileges) {
            authorities.add(new SimpleGrantedAuthority(privilege));
        }
        return authorities;
    }
}
