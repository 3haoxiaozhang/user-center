package com.yupi.usercenter.service;

import com.yupi.usercenter.model.domain.User;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import javax.annotation.Resource;





@SpringBootTest
class UserServiceTest {

    @Resource
    private UserService userService;


    @Test
    public void test(){
        User user=new User();
        user.setUsername("zzz");
        user.setUserAccount("123");
        user.setAvatarUrl("");
        user.setGender(0);
        user.setUserPassword("456");
        user.setPhone("1321");
        user.setEmail("465");
        user.setUserStatus(0);

       userService.save(user);

    }

    @Test
    void userRegister() {

        //检验非空
        String userAccount="yupi";
        String userPassword="";
        String checkPassword="123456";
        String planetCode="1";
        long result = userService.userRegister(userAccount, userPassword, checkPassword,planetCode);
        Assertions.assertEquals(-1,result);

        //账户不小于四位
        userAccount="yu";
        result = userService.userRegister(userAccount, userPassword, checkPassword,planetCode);
        Assertions.assertEquals(-1,result);

        //密码不小于8位
        userPassword="123456";
        userAccount="yupi";
        result = userService.userRegister(userAccount, userPassword, checkPassword,planetCode);
        Assertions.assertEquals(-1,result);

        //不包含特殊字符
        userAccount="yu pi";
        userPassword="12345678";
        checkPassword="12345678";
        result = userService.userRegister(userAccount, userPassword, checkPassword,planetCode);
        Assertions.assertEquals(-1,result);

        //密码和校验密码相同
        checkPassword="123456789";
        result = userService.userRegister(userAccount, userPassword, checkPassword,planetCode);
        Assertions.assertEquals(-1,result);

        //账户不能相同
        userAccount="dogyupi";
        userPassword="12345678";
        checkPassword="12345678";
        result = userService.userRegister(userAccount, userPassword, checkPassword,planetCode);
        Assertions.assertEquals(-1,result);


        userAccount="aibiancheng";
        userPassword="12345678";
        checkPassword="12345678";
        result = userService.userRegister(userAccount, userPassword, checkPassword,planetCode);
        Assertions.assertEquals(-1,result);




    }
}