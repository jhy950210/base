package com.plate.hy.controller

import io.swagger.v3.oas.annotations.Operation
import org.springframework.web.bind.annotation.GetMapping
import io.swagger.v3.oas.annotations.tags.Tag
import org.springframework.web.bind.annotation.RestController

@Tag(name = "멤버 api")
@RestController
class MemberController {

    @Operation(summary = "test")
    @GetMapping("/test")
    fun getHello(): String {
        return "Hello, base-project"
    }
}
