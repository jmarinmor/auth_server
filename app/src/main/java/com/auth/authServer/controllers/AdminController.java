package com.auth.authServer.controllers;

import com.auth.authServer.model.Application;
import com.servers.interop.ErrorCode;
import com.servers.interop.requests.AddUserFieldRequest;
import com.servers.interop.requests.GenerateAdminKeysRequest;
import com.servers.interop.requests.SetAdminPublicKeyRequest;
import com.jcore.crypto.CipherUtils;
import com.servers.key.model.KeyDatabase;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyPair;

@RestController
@RequestMapping("/admin")
public class AdminController {

    @PostMapping(value = "/set_admin_pk")
    public SetAdminPublicKeyRequest.Response setAdminPrivateKeyCallback(@RequestBody @NonNull SetAdminPublicKeyRequest request) {
        SetAdminPublicKeyRequest.Response ret = new SetAdminPublicKeyRequest.Response();

//        try (KeyDatabase db = Application.getKeyDatabase()) {
//            ret.errorCode = db.setAdminPublicKey(request);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
        return ret;
    }

    @PostMapping(value = "/gen_admin_pk")
    public GenerateAdminKeysRequest.Response generateAdminPrivateKeyCallback(@RequestBody @NonNull GenerateAdminKeysRequest request) {
        GenerateAdminKeysRequest.Response ret = new GenerateAdminKeysRequest.Response();

        try (KeyDatabase db = Application.getKeyDatabase()) {
            KeyPair pair = db.generateKeyPair();
            if (pair != null) {
                ret.response = new GenerateAdminKeysRequest.Response.Content(
                        CipherUtils.getPublicKeyInBase64(pair),
                        CipherUtils.getPrivateKeyInBase64(pair)
                );
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

//        try (AuthDatabase db = Application.getAuthDatabase()) {
//            //byte[] value = Base64.getUrlDecoder().decode(request.addFieldObject);
//            ret.errorCode = db.addUserPropertyField(request);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
        return ret;
    }

}
