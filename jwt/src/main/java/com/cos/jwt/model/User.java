package com.cos.jwt.model;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Entity
@Data
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    // 이렇게 하면 mysql을 사용하면 auto increment 된다.
    private long id;
    private String username;
    private String password;
    private String roles; // USER, ADMIN

    // roles 스트링에 "USER, ADMIN"들어간 경우 ','로 나눠서 리스트로 반환한다.
    public List<String> getRoleList(){
        if(this.roles.length() > 0){
            return Arrays.asList(this.roles.split(","));
        }
        return new ArrayList<>();
    }

}
