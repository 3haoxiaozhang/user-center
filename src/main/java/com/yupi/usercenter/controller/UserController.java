package com.yupi.usercenter.controller;


import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.yupi.usercenter.common.BaseResponse;
import com.yupi.usercenter.common.ErrorCode;
import com.yupi.usercenter.common.ResultUtils;
import com.yupi.usercenter.contant.UserConstant;
import com.yupi.usercenter.exception.BusinessException;
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
    public BaseResponse<Long> userRegister(@RequestBody UserRegisterRequest userRegisterRequest){
        if(userRegisterRequest==null){
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        String userAccount = userRegisterRequest.getUserAccount();
        String userPassword = userRegisterRequest.getUserPassword();
        String checkPassword = userRegisterRequest.getCheckPassword();
        String planetCode = userRegisterRequest.getPlanetCode();
        if(StringUtils.isAnyBlank(userAccount,userPassword,checkPassword,planetCode)){
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        long id = userService.userRegister(userAccount, userPassword, checkPassword,planetCode);

        return ResultUtils.success(id);
    }

    /**
     * 登录
     * @param userLoginRequest
     * @param request
     * @return
     */
    @PostMapping("/login")
    public BaseResponse<User> userLogin(@RequestBody UserLoginRequest userLoginRequest, HttpServletRequest request){
        if(userLoginRequest==null){
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        String userAccount = userLoginRequest.getUserAccount();
        String userPassword =userLoginRequest.getUserPassword();

        if(StringUtils.isAnyBlank(userAccount,userPassword)){
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }

        User user = userService.userLogin(userAccount, userPassword, request);
        return ResultUtils.success(user);
    }


    @PostMapping("/logout")
    public BaseResponse<Integer> logout(HttpServletRequest request){
       if(request == null){
           throw new BusinessException(ErrorCode.NOT_LOGIN);
       }

        return ResultUtils.success(userService.userLogout(request));
    }

    /**
     * 给前端返回用户
     * @param Request
     * @return
     */
    @GetMapping("/current")
    public BaseResponse<User> getCurrentUser(HttpServletRequest Request){
        Object UserObj = Request.getSession().getAttribute(UserConstant.USER_LOGIN_STATE);
        User currentUser=(User)UserObj;
        if(currentUser==null){
            throw new BusinessException(ErrorCode.NOT_LOGIN);
        }
        Long userId = currentUser.getId();
        //todo 校验用户是否合法
        User user = userService.getById(userId);
        User safetyUser = userService.getSafetyUser(user);
        return ResultUtils.success(safetyUser);
    }


    /**
     *根据用户名查询
     * @param username
     * @param Request
     * @return
     */
    @GetMapping("/search")
    public BaseResponse<List<User>> searchList(String username,HttpServletRequest Request){

        if (!isAdmin(Request)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        QueryWrapper<User> queryWrapper=new QueryWrapper<>();
        if(StringUtils.isNotBlank(username)){
            queryWrapper.like("username",username);
        }

        List<User> list = userService.list(queryWrapper);
        List<User> userList = list.stream().map(user ->
                userService.getSafetyUser(user)
                 ).collect(Collectors.toList());
        return ResultUtils.success(userList);

    }

    /**
     * 根据id删除
     * @param id
     * @param Request
     * @return
     */
    @PostMapping("/delete")
    public BaseResponse<Boolean> deleteUser(@RequestBody Long id,HttpServletRequest Request){

       if(!isAdmin(Request)){
           throw new BusinessException(ErrorCode.NO_AUTH);
        }
       if(id<=0){
           throw new BusinessException(ErrorCode.PARAMS_ERROR);
       }
        boolean result = userService.removeById(id);
        return ResultUtils.success(result);
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
