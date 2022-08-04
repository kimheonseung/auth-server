package com.devh.project.authserver.repository;

import com.devh.project.authserver.domain.item.Book;
import com.devh.project.authserver.domain.item.Item;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@TestPropertySource(properties = {"spring.config.location=classpath:application-test.yml"})
public class ItemRepositoryTests {
    @Autowired
    ItemRepository itemRepository;

    @Test
    public void save() {
        // given
        final String givenAuthor = "hskim";
        final String givenIsbn = "abcd";
        final String givenName = "hskimBook";
        final int givenPrice = 1000;
        final int givenStockQuantity = 5;
        Book book = new Book();
        book.setAuthor(givenAuthor);
        book.setIsbn(givenIsbn);
        book.setName(givenName);
        book.setPrice(givenPrice);
        book.setStockQuantity(givenStockQuantity);
        // when
        Item item = itemRepository.save(book);
        // then
        assertEquals(item.getName(), givenName);
        assertEquals(item.getPrice(), givenPrice);
        assertEquals(item.getStockQuantity(), givenStockQuantity);
    }
}
