package org.login.persistence.dao;

import org.login.persistence.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface UserDAO extends JpaRepository<User, Long> {

    User getUserByUsername(@Param("username") String username);
    List<String> getAuthorities(@Param("userId") Long userId);
}