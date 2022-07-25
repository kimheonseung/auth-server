package com.devh.project.common.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * <pre>
 * Description :
 *     API 요청/응답에 함께 전송될 페이징 정보 객체
 * ===============================================
 * Member fields :
 *
 * ===============================================
 *
 * Author : HeonSeung Kim
 * Date   : 2022. 7. 14.
 * </pre>
 */
@Builder
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class PagingDTO {
    /* 총 데이터 갯수 */
    private long total;
    /* 한 페이지에 보여질 갯수 */
    private int rows;
    /* 현재 페이지 번호 */
    private int page;
    /* 목록 사이즈 */
    private static int pageListSize = 5;
    /* 총 페이지 번호 */
    private int totalPage;
    /* 시작 페이지 번호, 끝 페이지 번호 */
    private int start, end;
    /* 이전, 다음 */
    private boolean prev, next;
    /* 페이지 번호 목록 */
    private List<Integer> pageList;

    public static PagingDTO build(int page, int rows, long total) {

        final int tempEnd = (int) (Math.ceil(page / (double) pageListSize)) * pageListSize;
        final int start = tempEnd - (pageListSize - 1);
        final int totalPage = (int) Math.ceil(total / (double) rows);
        final int end = Math.min(totalPage, tempEnd);

        return PagingDTO.builder()
                .page(page)
//                .size(size)
                .rows(rows)
                .total(total)
                .totalPage(totalPage)
                .start(start)
                .prev(start > 1)
                .next(totalPage > tempEnd)
                .end(end)
                .pageList(IntStream.rangeClosed(start, end).boxed().collect(Collectors.toList()))
                .build();
    }
}