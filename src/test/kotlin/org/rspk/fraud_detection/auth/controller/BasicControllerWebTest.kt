package org.rspk.fraud_detection.auth.controller
import org.junit.jupiter.api.Test
import org.rspk.fraud_detection.auth.AuthServiceApplication
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status


/*controller testing - checking the /health api endpoint was giving correct responses */
@WebMvcTest(
    controllers = [BasicController::class],
//    properties = ["spring.main.allow-bean-definition-overriding=true"]
) /* starts only the component we want to test */
//@ContextConfiguration(classes = [AuthServiceApplication::class]) /* spring unable to detect the main application class automatically so we specified it explicitly*/
class BasicControllerWebTest {

    @Autowired
    lateinit var mockMvc: MockMvc


    @Test
    fun `GET health should return success response`() {
        mockMvc.perform(get("/health"))
            .andExpect(status().isOk)
            .andExpect(content().string("fraud authentication is active"))
    }

}