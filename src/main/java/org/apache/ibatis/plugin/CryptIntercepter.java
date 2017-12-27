package org.apache.ibatis.plugin;

import org.apache.commons.lang3.StringUtils;
import org.apache.ibatis.annotations.CryptField;
import org.apache.ibatis.binding.MapperMethod;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;
import org.apache.ibatis.session.defaults.DefaultSqlSession;

import java.io.UnsupportedEncodingException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 项目：mybatis-crypt
 * 包名：org.apache.ibatis.plugin
 * 功能：数据库数据脱敏
 * 加解密算法推荐：aes192 + base64
 * 时间：2017-11-22
 * 作者：miaoxw
 */
@Intercepts({
        @Signature(type = Executor.class, method = "update", args = {MappedStatement.class, Object.class}),
        @Signature(type = Executor.class, method = "query", args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class})
})
public class CryptIntercepter implements Interceptor {

    /**
     * 适用于解密判断
     */
    private static final ConcurrentHashMap<String, Boolean> METHOD_ANNOTATIONS_MAP = new ConcurrentHashMap<>();
    /**
     * 适用于加密判断
     */
    private static final ConcurrentHashMap<String, Set<String>> METHOD_PARAM_ANNOTATIONS_MAP = new ConcurrentHashMap<>();

    public CryptIntercepter() {

    }

    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        Object[] args = invocation.getArgs();
        // 入参
        Object parameter = args[1];
        MappedStatement statement = (MappedStatement) args[0];
        // 判断是否需要解析
        if (!isNotCrypt(parameter)) {
            // 单参数 string
            if (parameter instanceof String) {
                args[1] = stringEncrypt((String) parameter, getParameterAnnotations(statement));
                // 单参数 list
            } else if (parameter instanceof DefaultSqlSession.StrictMap) {
                DefaultSqlSession.StrictMap<Object> strictMap = (DefaultSqlSession.StrictMap<Object>) parameter;
                for (Map.Entry<String, Object> entry : strictMap.entrySet()) {
                    if (entry.getKey().contains("collection")) {
                        continue;
                    }
                    if (entry.getKey().contains("list")) {
                        Set<String> set = getParameterAnnotations(statement);
                        listEncrypt((List) entry.getValue(), !set.isEmpty());
                    }
                }
                // 多参数
            } else if (parameter instanceof MapperMethod.ParamMap) {
                MapperMethod.ParamMap<Object> paramMap = (MapperMethod.ParamMap<Object>) parameter;
                Set<String> set = getParameterAnnotations(statement);
                boolean setEmpty = set.isEmpty();
                // 解析每一个参数
                for (Map.Entry<String, Object> entry : paramMap.entrySet()) {
                    // 判断不需要解析的类型 不解析map
                    if (isNotCrypt(entry.getValue()) || entry.getValue() instanceof Map || entry.getKey().contains("param")) {
                        continue;
                    }
                    // 如果string
                    if (entry.getValue() instanceof String) {
                        entry.setValue(stringEncrypt(entry.getKey(), (String) entry.getValue(), set));
                        continue;
                    }
                    boolean isSetValue = !setEmpty && set.contains(entry.getKey());
                    // 如果 list
                    if (entry.getValue() instanceof List) {
                        listEncrypt((List) entry.getValue(), isSetValue);
                        continue;
                    }
                    beanEncrypt(entry.getValue());
                }
                // bean
            } else {
                beanEncrypt(parameter);
            }
        }

        // 获得出参
        Object returnValue = invocation.proceed();

        // 出参解密
        if (isNotCrypt(returnValue)) {
            return returnValue;
        }
        Boolean bo = getMethodAnnotations(statement);
        if (returnValue instanceof String && bo) {
            return stringDecrypt((String) returnValue);
        }
        if (returnValue instanceof List) {
            listDecrypt((List) returnValue, bo);
            return returnValue;
        }

        return returnValue;
    }

    @Override
    public Object plugin(Object target) {
        return Plugin.wrap(target, this);
    }

    @Override
    public void setProperties(Properties properties) {

    }

    /**
     * 获取 方法上的注解
     *
     * @param statement
     * @return
     * @throws ClassNotFoundException
     */
    private Boolean getMethodAnnotations(MappedStatement statement) throws ClassNotFoundException {
        final String id = statement.getId();
        Boolean bo = METHOD_ANNOTATIONS_MAP.get(id);
        if (bo != null) {
            return bo;
        }
        Method m = null;
        final Class clazz = Class.forName(id.substring(0, id.lastIndexOf(".")));
        for (Method method : clazz.getMethods()) {
            if (method.getName().equals(id.substring(id.lastIndexOf(".") + 1))) {
                m = method;
                break;
            }
        }
        if (m == null) {
            return Boolean.FALSE;
        }
        final CryptField cryptField = m.getAnnotation(CryptField.class);
        // 如果允许解密
        if (cryptField != null && cryptField.decrypt()) {
            bo = Boolean.TRUE;
        } else {
            bo = Boolean.FALSE;
        }
        Boolean bo1 = METHOD_ANNOTATIONS_MAP.putIfAbsent(id, bo);
        if (bo1 != null) {
            bo = bo1;
        }

        return bo;
    }

    /**
     * 获取 方法参数上的注解
     *
     * @param statement
     * @return
     * @throws ClassNotFoundException
     */
    private Set<String> getParameterAnnotations(MappedStatement statement) throws ClassNotFoundException {
        final String id = statement.getId();
        Set<String> set = METHOD_PARAM_ANNOTATIONS_MAP.get(id);
        if (set != null) {
            return set;
        }
        set = new HashSet<>();
        Method m = null;
        final Class clazz = Class.forName(id.substring(0, id.lastIndexOf(".")));
        for (Method method : clazz.getMethods()) {
            if (method.getName().equals(id.substring(id.lastIndexOf(".") + 1))) {
                m = method;
                break;
            }
        }
        if (m == null) {
            return set;
        }
        final Annotation[][] paramAnnotations = m.getParameterAnnotations();
        // get names from @CryptField annotations
        for (Annotation[] paramAnnotation : paramAnnotations) {
            for (Annotation annotation : paramAnnotation) {
                if (annotation instanceof CryptField) {
                    CryptField cryptField = (CryptField) annotation;
                    // 如果允许加密
                    if (cryptField.encrypt()) {
                        set.add(cryptField.value());
                    }
                    break;
                }
            }
        }

        Set<String> oldSet = METHOD_PARAM_ANNOTATIONS_MAP.putIfAbsent(id, set);
        if (oldSet != null) {
            set = oldSet;
        }

        return set;
    }

    /**
     * 判断是否需要加解密
     *
     * @param o
     * @return
     */
    private boolean isNotCrypt(Object o) {
        return o == null || o instanceof Double || o instanceof Integer || o instanceof Long || o instanceof Boolean;
    }

    /**
     * String 加密
     *
     * @param str
     * @return
     * @throws UnsupportedEncodingException
     */
    private String stringEncrypt(String str) throws UnsupportedEncodingException {
        return stringEncrypt(null, str, null, null);
    }

    /**
     * String 加密
     *
     * @param str
     * @param set
     * @return
     * @throws UnsupportedEncodingException
     */
    private String stringEncrypt(String str, Set<String> set) throws UnsupportedEncodingException {
        return stringEncrypt(null, str, set, true);
    }

    /**
     * String 加密
     *
     * @param name
     * @param str
     * @param set
     * @return
     * @throws UnsupportedEncodingException
     */
    private String stringEncrypt(String name, String str, Set<String> set) throws UnsupportedEncodingException {
        return stringEncrypt(name, str, set, false);
    }

    /**
     * String 加密
     *
     * @param name
     * @param str
     * @param set
     * @param isSingle
     * @return
     * @throws UnsupportedEncodingException
     */
    private String stringEncrypt(String name, String str, Set<String> set, Boolean isSingle) {
        if (StringUtils.isBlank(str)) {
            return str;
        }
        if (isSingle == null) {
            //todo 加密实现
            str = "";
            return str;
        }
        if (isSingle && set != null && !set.isEmpty()) {
            //todo 加密实现
            str = "";
            return str;
        }
        if (!isSingle && set != null && !set.isEmpty() && set.contains(name)) {
            //todo 加密实现
            str = "";
            return str;
        }

        return str;
    }

    /**
     * String 解密
     *
     * @param str
     * @return
     * @throws UnsupportedEncodingException
     */
    private String stringDecrypt(String str) {
        if (StringUtils.isBlank(str)) {
            return str;
        }
        String[] array = str.split("\\|");
        if (array.length < 2) {
            return str;
        }
        //todo 解密实现
        str = "";

        return str;
    }

    /**
     * list 加密
     *
     * @param list
     * @param bo
     * @return
     * @throws Exception
     */
    private List listEncrypt(List list, Boolean bo) throws Exception {
        for (int i = 0; i < list.size(); i++) {
            Object listValue = list.get(i);
            // 判断不需要解析的类型
            if (isNotCrypt(listValue) || listValue instanceof Map) {
                break;
            }
            if (listValue instanceof String && bo) {
                list.set(i, stringEncrypt((String) listValue));
                continue;
            }
            beanEncrypt(listValue);
        }

        return list;
    }

    /**
     * list 解密
     *
     * @param list
     * @param bo
     * @return
     * @throws Exception
     */
    private List listDecrypt(List list, Boolean bo) throws Exception {
        for (int i = 0; i < list.size(); i++) {
            Object listValue = list.get(i);
            // 判断不需要解析的类型 获得
            if (isNotCrypt(listValue) || listValue instanceof Map) {
                break;
            }
            if (listValue instanceof String && bo) {
                list.set(i, stringDecrypt((String) listValue));
                continue;
            }
            beanDecrypt(listValue);
        }

        return list;
    }

    /**
     * bean 加密
     *
     * @param val
     * @throws IllegalAccessException
     */
    private void beanEncrypt(Object val) throws Exception {
        Class objClazz = val.getClass();
        Field[] objFields = objClazz.getDeclaredFields();
        for (Field field : objFields) {
            CryptField cryptField = field.getAnnotation(CryptField.class);
            if (cryptField != null && cryptField.encrypt()) {
                field.setAccessible(true);
                Object fieldValue = field.get(val);
                if (fieldValue == null) {
                    continue;
                }
                if (field.getType().equals(String.class)) {
                    field.set(val, stringEncrypt((String) fieldValue));
                    continue;
                }
                if (field.getType().equals(List.class)) {
                    field.set(val, listEncrypt((List) fieldValue, Boolean.TRUE));
                    continue;
                }
            }
        }
    }

    /**
     * bean 解密
     *
     * @param val
     * @throws IllegalAccessException
     */
    private void beanDecrypt(Object val) throws Exception {
        Class objClazz = val.getClass();
        Field[] objFields = objClazz.getDeclaredFields();
        for (Field field : objFields) {
            CryptField cryptField = field.getAnnotation(CryptField.class);
            if (cryptField != null && cryptField.decrypt()) {
                field.setAccessible(true);
                Object fieldValue = field.get(val);
                if (fieldValue == null) {
                    continue;
                }
                if (field.getType().equals(String.class)) {
                    field.set(val, stringDecrypt((String) fieldValue));
                    continue;
                }
                if (field.getType().equals(List.class)) {
                    field.set(val, listDecrypt((List) fieldValue, Boolean.TRUE));
                    continue;
                }
            }
        }
    }
}
