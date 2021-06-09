package com.auth.authServer.controllers;

import com.auth.authServer.model.Application;
import com.auth.interop.Captcha;
import com.google.gson.Gson;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/app")
public class AppController {

    private static Gson mGson = new Gson();

//    @PostMapping(value = "/init/demand")
//    public App.DemandResult initDemand() {
//        if (Application.getDatabase().getUserCount() > 0)
//            return new App.DemandResult(false, null);
//
//        Captcha captcha = Application.getDatabase().demandNewCaptcha();
//
//        if (Application.DEBUG_MODE) {
//            System.out.println("SERVICE: app/init/demand");
//            System.out.println(mGson.toJson(captcha));
//        }
//
//        return new App.DemandResult(true, captcha);
//    }
//
//    @PostMapping(value = "/init/perform")
//    public App.InitResult initPerform(@RequestBody App.InitRequest request) {
//        if (request == null)
//            return new App.InitResult(false, false, false, false);
//
//        boolean valid_password = request.password != null;
//        boolean valid_mail = request.email != null && request.isValidEmail();
//        boolean valid_captcha = Application.getDatabase().verifyCaptcha(request.capchaId, request.capchaValue);
//
//        App.InitResult result = new App.InitResult(true, valid_mail, valid_captcha, valid_password);
//
//        if (Application.DEBUG_MODE) {
//            System.out.println("SERVICE: app/init/perform");
//            System.out.println(mGson.toJson(result));
//            System.out.println("sending a message to " + request.email);
//        }
//
//        return result;
//    }

}
