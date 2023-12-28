package com.baeldung.lsso;

import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.opaqueToken;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
public class ResourceServerIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Test
    public void givenOpaqueToken_whenHttpGet_thenOk() throws Exception {
        this.mvc.perform(get("/api/projects").with(opaqueToken())
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.size()", Matchers.greaterThan(0)));
    }

    @Test
    public void notGivenOpaqueToken_whenHttpGet_thenUnauthorized() throws Exception {
        this.mvc.perform(get("/api/projects"))
            .andExpect(status().isUnauthorized())
            .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"));
    }

    @Test
    public void givenOpaqueTokenAndOnlyWriteScope_whenHttpGet_thenForbidden() throws Exception {
        this.mvc.perform(get("/api/projects").with(opaqueToken().attributes(attrs -> attrs.put("scope", "write")))
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isForbidden())
            .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
                allOf(containsString("insufficient_scope"), containsString("The request requires higher privileges than provided by the access token"))));
    }

    @Test
    public void givenOpaqueTokenAndReadScope_whenHttpGet_thenOk() throws Exception {
        this.mvc.perform(get("/api/projects").with(opaqueToken().attributes(attrs -> attrs.put("scope", "read")))
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.size()", Matchers.greaterThan(0)));
    }

    @Test
    public void givenOpaqueTokenAndWriteScope_whenHttpPost_thenOk() throws Exception {
        this.mvc.perform(post("/api/projects").with(opaqueToken().attributes(attrs -> attrs.put("scope", "write")))
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"Project 1\",\"dateCreated\":\"2019-06-13\"}"))
            .andExpect(status().isCreated());
    }

    @Test
    public void givenOpaqueTokenAndOnlyReadScope_whenHttpPost_thenForbidden() throws Exception {
        this.mvc.perform(post("/api/projects").with(opaqueToken().attributes(attrs -> attrs.put("scope", "read")))
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"id\":1,\"name\":\"Project 1\",\"dateCreated\":\"2019-06-13\"}"))
            .andExpect(status().isForbidden())
            .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
                allOf(containsString("insufficient_scope"), containsString("The request requires higher privileges than provided by the access token"))));
    }
}