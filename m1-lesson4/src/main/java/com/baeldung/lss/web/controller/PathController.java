package com.baeldung.lss.web.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
@Controller
public class PathController {

    @RequestMapping(path = "/login")
    public String login() {
        return "loginPage";
    }

}
