package com.devh.project.authserver.service;

import com.devh.project.authserver.domain.Address;
import com.devh.project.authserver.domain.Member;
import com.devh.project.authserver.domain.Order;
import com.devh.project.authserver.domain.item.Book;
import com.devh.project.authserver.repository.ItemRepository;
import com.devh.project.authserver.repository.MemberRepository;
import com.devh.project.authserver.repository.OrderRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@ExtendWith(MockitoExtension.class)
@Transactional
public class OrderServiceTests {
    @Mock
    private ItemRepository itemRepository;
    @Mock
    private OrderRepository orderRepository;
    @Mock
    private MemberRepository memberRepository;
    @InjectMocks
    private OrderService orderService;

    @Test
    public void order() {
        // given
        final Long givenMemberId = 1L;
        final Address givenAddress = new Address();
        givenAddress.setCity("Incheon");
        givenAddress.setStreet("JangJeRo");
        givenAddress.setZipcode("21399");
        final Member givenMember = Member.builder()
                .id(givenMemberId)
                .name("hskim")
                .address(givenAddress)
                .build();
        final Long givenItemId = 1L;
        final Book givenItem = new Book();
        givenItem.setId(givenItemId);
        givenItem.setPrice(5000);
        givenItem.setName("elasticsearch");
        givenItem.setAuthor("hskim");
        givenItem.setIsbn("AAD#43");
        givenItem.setStockQuantity(15);
        final int givenCount = 5;
        given(memberRepository.findById(givenMemberId)).willReturn(Optional.of(givenMember));
        given(itemRepository.findById(givenItemId)).willReturn(Optional.of(givenItem));
        given(orderRepository.save(any(Order.class))).willAnswer(i -> {
            Order order = (Order) i.getArguments()[0];
            order.setId(486L);
            return order;
        });
        // when
        Long orderId = orderService.order(givenMemberId, givenItemId, givenCount);
        // then
        assertNotNull(orderId);
        assertEquals(orderId, 486);
    }
}
