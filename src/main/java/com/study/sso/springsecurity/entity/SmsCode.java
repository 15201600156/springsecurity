package com.study.sso.springsecurity.entity;

import lombok.Data;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * 短信验证码对象SmsCode
 */
@Data
public class SmsCode implements Serializable {
    /**
     * 验证码
     */
    private String code;
    /**
     * 过期时间
     */
    private LocalDateTime expireTime;

    public SmsCode(String code, int expireIn) {
        this.code = code;
        this.expireTime = LocalDateTime.now().plusSeconds(expireIn);
    }

    public SmsCode(String code, LocalDateTime expireTime) {
        this.code = code;
        this.expireTime = expireTime;
    }

    /**
     * isExpire方法用于判断短信验证码是否已过期。
     * @return
     */
    public boolean isExpire() {
        return LocalDateTime.now().isAfter(expireTime);
    }
}