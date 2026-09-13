package com.shiguangshe.common.api;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

/**
 * @ClassName: RustFSUploadResult
 * @Description: RustFS文件上传返回结果
 * @Author: ZM
 * @Date: 2026年09月12日  23:55
 **/
@Data
public class RustFSUploadResult {
    @Schema(title = "文件访问URL")
    private String url;
    @Schema(title = "文件名称")
    private String name;
}
