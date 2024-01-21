package com.yupi.usercenter.controller;


import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.yupi.usercenter.contant.UserConstant;
import com.yupi.usercenter.model.domain.User;
import com.yupi.usercenter.model.domain.request.UserLoginRequest;
import com.yupi.usercenter.model.domain.request.UserRegisterRequest;
import com.yupi.usercenter.service.UserService;
import org.apache.commons.lang3.StringUtils;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 用户接口
 * @author 张家霖
 */

@RestController
@RequestMapping("/user")
public class UserController {

    @Resource
    private UserService userService;

    /**
     * 注册
     * @param userRegisterRequest
     * @return
     */
    @PostMapping("/register")
    public Long userRegister(@RequestBody UserRegisterRequest userRegisterRequest){
        if(userRegisterRequest==null){
            return null;
        }
        String userAccount = userRegisterRequest.getUserAccount();
        String userPassword = userRegisterRequest.getUserPassword();
        String checkPassword = userRegisterRequest.getCheckPassword();
        if(StringUtils.isAnyBlank(userAccount,userPassword,checkPassword)){
            return null;
        }
        long id = userService.userRegister(userAccount, userPassword, checkPassword);

        return id;
    }

    /**
     * 登录
     * @param userLoginRequest
     * @param request
     * @return
     */
    @PostMapping("/login")
    public User userLogin(@RequestBody UserLoginRequest userLoginRequest, HttpServletRequest request){
        if(userLoginRequest==null){
            return null;
        }
        String userAccount = userLoginRequest.getUserAccount();
        String userPassword =userLoginRequest.getUserPassword();

        if(StringUtils.isAnyBlank(userAccount,userPassword)){
            return null;
        }

        User user = userService.userLogin(userAccount, userPassword, request);


        return user;
    }

    /**
     * 给前端返回用户
     * @param Request
     * @return
     */
    @GetMapping("/current")
    public User getCurrentUser(HttpServletRequest Request){
        Object UserObj = Request.getSession().getAttribute(UserConstant.USER_LOGIN_STATE);
        User currentUser=(User)UserObj;
        if(currentUser==null){
            return null;
        }
        Long userId = currentUser.getId();
        //todo 校验用户是否合法
        User user = userService.getById(userId);
        return userService.getSafetyUser(user);


    }


    /**
     *根据用户名查询
     * @param username
     * @param Request
     * @return
     */
    @GetMapping("/search")
    public List<User> searchList(String username,HttpServletRequest Request){

        if (!isAdmin(Request)) {
            return new ArrayList<>();
        }
        QueryWrapper<User> queryWrapper=new QueryWrapper<>();
        if(StringUtils.isNotBlank(username)){
            queryWrapper.like("username",username);
        }

        List<User> list = userService.list(queryWrapper);
        return list.stream().map(user->
               userService.getSafetyUser(user)
            ).collect(Collectors.toList());

    }

    /**
     * 根据id删除
     * @param id
     * @param Request
     * @return
     */
    @PostMapping("/delete")
    public boolean deleteUser(@RequestBody Long id,HttpServletRequest Request){

       if(!isAdmin(Request)){
           return false;
        }
       if(id<=0){
           return false;
       }
        boolean result = userService.removeById(id);
        return result;
    }

    /**
     * 是否为管理员
     * @param Request
     * @return
     */
    private boolean isAdmin(HttpServletRequest Request){
        //仅管理员可查询
        Object userObject = Request.getSession().getAttribute(UserConstant.USER_LOGIN_STATE);
        User user=(User)userObject;
        if(user==null||user.getUserRole()!=UserConstant.ADMIN_ROLE){
            return false;
        }
        return true;
    }

}
