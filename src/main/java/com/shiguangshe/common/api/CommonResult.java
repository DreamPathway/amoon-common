package com.shiguangshe.common.api;

import lombok.Data;


@Data
public class CommonResult<T> {

    private Integer code;
    private String message;
    private T data;

    public CommonResult() {
    }

    public CommonResult(Integer code, String message, T data) {
        this.code = code;
        this.message = message;
        this.data = data;
    }

    // 快捷成功方法
    public static <T> CommonResult<T> success(T data) {
        return new CommonResult<>(200, "操作成功", data);
    }

    // 快捷失败方法
    public static <T> CommonResult<T> error(String message) {
        return new CommonResult<>(500, message, null);
    }

}
