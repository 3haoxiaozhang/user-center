package com.yupi.usercenter.exception;

import com.yupi.usercenter.common.BaseResponse;
import com.yupi.usercenter.common.ErrorCode;
import com.yupi.usercenter.common.ResultUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 全局异常处理器
 */
@RestControllerAdvice//  spring aop切面功能  在执行代码前后进行封装
@Slf4j
public class GlobalExceptionHanlder {

    //针对什么异常做什么处理
    @ExceptionHandler(BusinessException.class)  //表示方法只捕获这个异常
    public BaseResponse businessExceptionHandler(BusinessException e){
        log.error("businessException",e.getMessage(),e);
        return ResultUtils.error(e.getCode(),e.getMessage(),e.getDescription());
    }

    @ExceptionHandler(RuntimeException.class)  //表示只捕获runtime 异常
    public BaseResponse runtimeExceptionHandler(RuntimeException e){
        log.error("runtimeException",e);
      return ResultUtils.error(ErrorCode.SYSTEM_ERROR,e.getMessage(),"");
    }

}
