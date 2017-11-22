package org.apache.ibatis.annotations;

import java.lang.annotation.*;

/**
 * 项目：mybatis-crypt
 * 包名：org.apache.ibatis.annotations
 * 功能：
 * 时间：2017-11-22
 * 作者：miaoxw
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.METHOD})
public @interface CryptField {

    String value() default "";

    boolean encrypt() default true;

    boolean decrypt() default true;
}
