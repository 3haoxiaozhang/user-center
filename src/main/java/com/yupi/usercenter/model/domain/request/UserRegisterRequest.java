package com.yupi.usercenter.model.domain.request;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.Serializable;

/**
 * 用户注册请求体
 * @author 张家霖
 */

@Data
public class UserRegisterRequest implements Serializable {

    private String userAccount;

    private String userPassword;

    private String checkPassword;

    private String planetCode;

}
