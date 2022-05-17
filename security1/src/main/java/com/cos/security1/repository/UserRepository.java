package com.cos.security1.repository;

import com.cos.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

// CRUD 함수를 JpaRepository가 들고 있음.
// @Repository라는 어노테이션이 없어도 IoC된다. 이유는 JpaRepository를 상속했기 때문이다.
public interface UserRepository extends JpaRepository<User, Integer> {
    // 기본 CRUD가 아니므로 findByUsername 함수를 생성한다.
    // findBy까지는 Spring Data JPA의 규칙이다. 그 후의 Username은 문법이다.
    // 'select * form user where username = ?' 호출된다.
    // 'select * from user where email = ?'
    // public User findByEmail();
    public User findByUsername(String username); // Jpa query methods 라고 한다.


}
