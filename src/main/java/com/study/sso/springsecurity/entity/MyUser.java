package com.study.sso.springsecurity.entity;

import lombok.Data;

import java.io.Serializable;

@Data
public class MyUser implements Serializable {
    private static final long serialVersionUID = 3497935890426858541L;
    //用于获取用户名
    private String userName;
    //用于获取密码
    private String password;
    //用于判断账户是否未过期，未过期返回true反之返回false；
    private boolean accountNonExpired = true;
    //方法用于判断账户是否未锁定；
    private boolean accountNonLocked= true;
    //用于判断用户凭证是否没过期，即密码是否未过期
    private boolean credentialsNonExpired= true;
    //方法用于判断用户是否可用
    private boolean enabled= true;
}