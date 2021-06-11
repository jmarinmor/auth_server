package com.auth.authServer.controllers;

import com.auth.authServer.model.Application;
import com.auth.authServer.model.AuthDatabase;
import com.auth.interop.ErrorCode;
import com.auth.interop.requests.AddUserFieldRequest;
import com.auth.interop.requests.GenerateAdminKeysRequest;
import com.auth.interop.requests.SetAdminPrivateKeyRequest;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;

@RestController
@RequestMapping("/admin")
public class AdminController {

    @PostMapping(value = "/set_admin_pk")
    public SetAdminPrivateKeyRequest.Response setAdminPrivateKeyCallback(@RequestBody @NonNull SetAdminPrivateKeyRequest request) {
        SetAdminPrivateKeyRequest.Response ret = new SetAdminPrivateKeyRequest.Response();

        try (AuthDatabase db = Application.getDatabase()) {
            ret.errorCode = db.setAdminPrivateKey(request.content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

    @PostMapping(value = "/gen_admin_pk")
    public GenerateAdminKeysRequest.Response generateAdminPrivateKeyCallback(@RequestBody @NonNull GenerateAdminKeysRequest request) {
        GenerateAdminKeysRequest.Response ret = new GenerateAdminKeysRequest.Response();

        try (AuthDatabase db = Application.getDatabase()) {
            byte[] key = db.generateAdminKeys(request.content);
            if (key != null) {
                String skey = Base64.getEncoder().encodeToString(key);
                ret.response = new GenerateAdminKeysRequest.Response.Content(skey);
                ret.errorCode = ErrorCode.SUCCEDED;
            } else {
                ret.errorCode = ErrorCode.INVALID_PARAMS;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

    @PostMapping(value = "/add_user_field")
    public AddUserFieldRequest.Response addUserFiledCallback(@RequestBody @NonNull AddUserFieldRequest request) {
        AddUserFieldRequest.Response ret = new AddUserFieldRequest.Response();

        try (AuthDatabase db = Application.getDatabase()) {
            //byte[] value = Base64.getUrlDecoder().decode(request.addFieldObject);
            ret.errorCode = db.addUserField(request.content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

}
