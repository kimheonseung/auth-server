package com.devh.project.common.util;

import java.io.PrintWriter;
import java.io.StringWriter;

/**
 * <pre>
 * Description :
 *     Exception 관련 처리 유틸
 * ===============================================
 * Member fields :
 *
 * ===============================================
 *
 * Author : HeonSeung Kim
 * Date   : 2022. 7. 14.
 * </pre>
 */
public class ExceptionUtils {

    /**
     * <pre>
     * Description
     *     Exception의 stackTrace를 문자열로 반환
     * ===============================================
     * Parameters
     *     Exception e
     * Returns
     *     String
     * Throws
     *
     * ===============================================
     *
     * Author : HeonSeung Kim
     * Date   : 2022. 7. 14.
     * </pre>
     */
    public static String stackTraceToString(Exception e) {
        StringWriter stringWriter = new StringWriter();
        e.printStackTrace(new PrintWriter(stringWriter));
        return stringWriter.toString();
    }
}