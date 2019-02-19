package com.sky.util;

import java.io.File;

/**
 * @program SelfIssueRsaDoubleCertificate
 * @description:
 * @author: daile
 * @create: 2019/02/19 21:03
 */
public class FileUtil {
    /**
     * 创建上层文件目录
     *
     * @param path
     */
    public static void createParentFilePath(String path) {
        File file = new File(path);
        File parentFile = file.getParentFile();

        if(!parentFile.exists()) {
            parentFile.mkdirs();
        }
    }
}
