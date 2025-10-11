package Model;

import Model.Request.CredentialListRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import Model.Request.DocumentDigests;
import Model.Enum.MobileDisplayTemplate;
import Model.Enum.SignAlgo;
import Model.Request.AuthorizeRequest;
import Model.Request.LoginRequest;
import Model.Request.SearchConditions;
import Model.Request.CredentialInfoRequest;
import Model.Request.SignHashRequest;
import Model.Response.AuthorizeResponse;
import Model.Response.CredentialInfoResponse;
import Model.Response.CredentialListResponse;
import Model.Response.LoginResponse;
import Model.Response.Response;
import Model.Response.SignHashResponse;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import API.HttpResponse;
import API.HttpUtils;
import API.ICertificate;
import API.IServerSession;
import API.Property;
import API.Utils;
import Model.Request.CredentialSendOTPRequest;
import Model.Response.BaseCertificateInfo;

public class ServerSession implements IServerSession {

    private String bearer;
    private String refreshToken;
    private Property property;
    private String lang;
    private String username;
    private String password;
    private int retryLogin = 0;

    public ServerSession(Property prop, String lang, String username, String password) throws Exception {
        this.property = prop;
        this.lang = lang;
        this.username = username;
        this.password = password;
        this.login();
    }

    @Override
    public boolean close() {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public void login() throws Exception {
        System.out.println("____________auth/login____________");
        String authHeader;

        if (refreshToken != null) {
            authHeader = refreshToken;
        } else {
            retryLogin++;
            authHeader = property.getAuthorization(this.username, this.password);
        }
        System.out.println("Login-retry: " + retryLogin);
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.rememberMeEnabled = true;
        loginRequest.relyingParty = property.relyingParty;
        loginRequest.lang = this.lang;

        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Authorization", authHeader);
        HttpResponse response = HttpUtils.invokeHttpRequest(property.baseUrl + "auth/login", "POST", 50000, headers, Utils.gsTmp.toJson(loginRequest));

        if (!response.isStatus()) {
            throw new Exception(response.getMsg());
        }

        LoginResponse signCloudResp = Utils.gsTmp.fromJson(response.getMsg(), LoginResponse.class);

        if (signCloudResp.error == 3005 || signCloudResp.error == 3006) {
            refreshToken = null;
            if (retryLogin >= 5) {
                retryLogin = 0;
                System.out.println("Response code: " + signCloudResp.error);
                System.out.println("Response Desscription: " + signCloudResp.errorDescription);
                System.out.println("Response ID: " + signCloudResp.responseID);
                System.out.println("AccessToken: " + signCloudResp.accessToken);
            }
            login();
        } else if (signCloudResp.error != 0) {
            System.out.println("Err code: " + signCloudResp.error);
            System.out.println("Err Desscription: " + signCloudResp.errorDescription);
            System.out.println("Response ID: " + signCloudResp.responseID);
        } else {
            this.bearer = "Bearer " + signCloudResp.accessToken;

            if (signCloudResp.refreshToken != null) {
                this.refreshToken = "Bearer " + signCloudResp.refreshToken;
                System.out.println("Err code: " + signCloudResp.error);
                System.out.println("Err Desscription: " + signCloudResp.errorDescription);
                System.out.println("Response ID: " + signCloudResp.responseID);
                System.out.println("AccessToken: " + signCloudResp.accessToken);
            }
        }
    }

    @Override
    public ICertificate certificateInfo(String credentialID) throws Exception {
        return certificateInfo(null, credentialID, null, false, false);
    }

    @Override
    public ICertificate certificateInfo(String agreementUUID, String credentialID) throws Exception {
        return certificateInfo(agreementUUID, credentialID, null, false, false);
    }

    @Override
    public ICertificate certificateInfo(String agreementUUID, String credentialID, String certificate, boolean certInfoEnabled, boolean authInfoEnabled) throws Exception {
        System.out.println("____________credentials/info____________");
        CredentialInfoRequest request = new CredentialInfoRequest();
        request.agreementUUID = agreementUUID;
        request.credentialID = credentialID;
        request.certificates = certificate;
        request.certInfoEnabled = certInfoEnabled;
        request.authInfoEnabled = authInfoEnabled;
        request.lang = this.lang;
        String authHeader = bearer;

        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Authorization", authHeader);
        HttpResponse response = HttpUtils.invokeHttpRequest(property.baseUrl + "credentials/info", "POST", 50000, headers, Utils.gsTmp.toJson(request));
        if (!response.isStatus()) {
            throw new Exception(response.getMsg());
        }

        CredentialInfoResponse signCloudResp = Utils.gsTmp.fromJson(response.getMsg(), CredentialInfoResponse.class);
        if (signCloudResp.error == 3005 || signCloudResp.error == 3006) {
            login();
            return certificateInfo(agreementUUID, credentialID, certificate, certInfoEnabled, authInfoEnabled);
        } else if (signCloudResp.error != 0) {
            //System.out.println("Err code: " + signCloudResp.error);
            //System.out.println("Err Desscription: " + signCloudResp.errorDescription);
            throw new APIException(signCloudResp.error, signCloudResp.errorDescription);
        }
        System.out.println("err code: " + signCloudResp.error);
        System.out.println("error description: " + signCloudResp.errorDescription);

        ICertificate iCrt = (ICertificate) new Certificate(signCloudResp.cert, agreementUUID, this);
        signCloudResp.cert.authorizationEmail = signCloudResp.authorizationEmail;
        signCloudResp.cert.authorizationPhone = signCloudResp.authorizationPhone;
        signCloudResp.cert.sharedMode = signCloudResp.sharedMode;
        signCloudResp.cert.createdRP = signCloudResp.createdRP;
        signCloudResp.cert.authModes = signCloudResp.authModes;
        signCloudResp.cert.authMode = signCloudResp.authMode;
        signCloudResp.cert.SCAL = signCloudResp.SCAL;
        signCloudResp.cert.contractExpirationDate = signCloudResp.contractExpirationDate;
        signCloudResp.cert.defaultPassphraseEnabled = signCloudResp.defaultPassphraseEnabled;
        signCloudResp.cert.trialEnabled = signCloudResp.trialEnabled;
        return iCrt;
    }

    @Override
    public String authorize(String agreementUUID, String credentialID, int numSignatures, DocumentDigests doc, SignAlgo signAlgo, String authorizeCode) throws Exception {
        return authorize(agreementUUID, credentialID, numSignatures, doc, signAlgo, null, authorizeCode);
    }

    @Override
    public String authorize(String agreementUUID, String credentialID, int numSignatures, DocumentDigests doc, SignAlgo signAlgo, String otpRequestID, String otp) throws Exception {
        System.out.println("____________credentials/authorize____________");
        AuthorizeRequest request = new AuthorizeRequest();
        request.agreementUUID = agreementUUID;
        request.credentialID = credentialID;
        request.numSignatures = numSignatures;
        request.documentDigests = doc;
        request.signAlgo = signAlgo;
        request.requestID = otpRequestID;
        request.authorizeCode = otp;
        request.lang = this.lang;
        String authHeader = bearer;

        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Authorization", authHeader);
        HttpResponse response = HttpUtils.invokeHttpRequest(property.baseUrl + "credentials/authorize", "POST", 50000, headers, Utils.gsTmp.toJson(request));

        if (!response.isStatus()) {
            throw new Exception(response.getMsg());
        }
        AuthorizeResponse signCloudResp = Utils.gsTmp.fromJson(response.getMsg(), AuthorizeResponse.class);
        if (signCloudResp.error == 3005 || signCloudResp.error == 3006) {
            login();
            return authorize(agreementUUID, credentialID, numSignatures, doc, signAlgo, otpRequestID, otp);
        } else if (signCloudResp.error != 0) {
            System.out.println("Err code: " + signCloudResp.error);
            System.out.println("Err Desscription: " + signCloudResp.errorDescription);
        }

        System.out.println("err code: " + signCloudResp.error);
        System.out.println("error description: " + signCloudResp.errorDescription);
        return signCloudResp.SAD;
    }

    @Override
    public String authorize(String agreementUUID, String credentialID, int numSignatures, DocumentDigests doc, SignAlgo signAlgo, MobileDisplayTemplate displayTemplate) throws Exception {
        System.out.println("____________credentials/authorize____________");
        AuthorizeRequest request = new AuthorizeRequest();
        request.agreementUUID = agreementUUID;
        request.credentialID = credentialID;
        request.numSignatures = numSignatures;
        request.documentDigests = doc;
        request.signAlgo = signAlgo;
        request.notificationMessage = displayTemplate.notificationMessage;
        request.messageCaption = displayTemplate.messageCaption;
        request.message = displayTemplate.message;
        request.logoURI = displayTemplate.logoURI;
        request.rpIconURI = displayTemplate.rpIconURI;
        request.bgImageURI = displayTemplate.bgImageURI;
        request.rpName = displayTemplate.rpName;
        request.scaIdentity = displayTemplate.scaIdentity;
        request.vcEnabled = displayTemplate.vcEnabled;
        request.acEnabled = displayTemplate.acEnabled;
        request.lang = this.lang;

        String authHeader = bearer;
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Authorization", authHeader);
        HttpResponse response = HttpUtils.invokeHttpRequest(property.baseUrl + "credentials/authorize", "POST", 50000, headers, Utils.gsTmp.toJson(request));

        if (!response.isStatus()) {
            try {
                throw new Exception(response.getMsg());
            } catch (Exception ex) {
                Logger.getLogger(ServerSession.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        AuthorizeResponse signCloudResp = Utils.gsTmp.fromJson(response.getMsg(), AuthorizeResponse.class);
        if (signCloudResp.error == 3005 || signCloudResp.error == 3006) {
            try {
                login();
            } catch (Exception ex) {
                Logger.getLogger(ServerSession.class.getName()).log(Level.SEVERE, null, ex);
            }
            return authorize(agreementUUID, credentialID, numSignatures, doc, signAlgo, displayTemplate);
        } else if (signCloudResp.error != 0) {
            System.out.println("err code: " + signCloudResp.error);
            System.out.println("error description: " + signCloudResp.errorDescription);
        }
        return signCloudResp.SAD;
    }

    @Override
    public List<byte[]> signHash(String agreementUUID, String credentialID, DocumentDigests documentDigest, SignAlgo signAlgo, String SAD) throws Exception {
        System.out.println("____________signatures/signHash____________");
        SignHashRequest request = new SignHashRequest();
        //request.agreementUUID = agreementUUID;
        request.credentialID = credentialID;
        request.documentDigests = documentDigest;
        request.signAlgo = signAlgo;
        request.SAD = SAD;
        request.lang = this.lang;

        String authHeader = bearer;

        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Authorization", authHeader);
        HttpResponse response = HttpUtils.invokeHttpRequest(property.baseUrl + "signatures/signHash", "POST", 50000, headers, Utils.gsTmp.toJson(request));
        if (!response.isStatus()) {
            throw new Exception(response.getMsg());
        }

        SignHashResponse signCloudResp = Utils.gsTmp.fromJson(response.getMsg(), SignHashResponse.class);
        if (signCloudResp.error == 3005 || signCloudResp.error == 3006) {
            login();
            return signHash(agreementUUID, credentialID, documentDigest, signAlgo, SAD);
        } else if (signCloudResp.error != 0) {
            System.out.println("Err code: " + signCloudResp.error);
            System.out.println("Err Desscription: " + signCloudResp.errorDescription);
        }
        System.out.println("err code: " + signCloudResp.error);
        System.out.println("error description: " + signCloudResp.errorDescription);
        return signCloudResp.signatures;
    }

    @Override
    public List<ICertificate> listCertificates() throws Exception {
        return listCertificates(null, null, false, false, null);
    }

    @Override
    public List<ICertificate> listCertificates(String agreementUUID) throws Exception {
        return listCertificates(agreementUUID, null, false, false, null);
    }

    @Override
    public List<ICertificate> listCertificates(String agreementUUID, String certificate, boolean certInfoEnabled, boolean authInfoEnabled, SearchConditions conditions) throws Exception {
        System.out.println("____________credentials/list____________");
        String authHeader = bearer;
        CredentialListRequest credentiallistRequest = new CredentialListRequest();
        credentiallistRequest.agreementUUID = agreementUUID;
        credentiallistRequest.certificates = certificate;
        credentiallistRequest.certInfoEnabled = certInfoEnabled;
        credentiallistRequest.authInfoEnabled = authInfoEnabled;
        credentiallistRequest.searchConditions = conditions;
        credentiallistRequest.lang = this.lang;

        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Authorization", authHeader);
        HttpResponse response = HttpUtils.invokeHttpRequest(property.baseUrl + "credentials/list", "POST", 50000, headers, Utils.gsTmp.toJson(credentiallistRequest));

        if (!response.isStatus()) {
            throw new Exception(response.getMsg());
        }

        CredentialListResponse signCloudResp = Utils.gsTmp.fromJson(response.getMsg(), CredentialListResponse.class);
        if (signCloudResp.error == 3005 || signCloudResp.error == 3006) {
            login();
            return listCertificates(agreementUUID, certificate, certInfoEnabled, authInfoEnabled, conditions);
        } else if (signCloudResp.error != 0) {
            throw new APIException(signCloudResp.error, signCloudResp.errorDescription);
        }
        List<BaseCertificateInfo> listCert = signCloudResp.certs;
        List<ICertificate> listCertificate = new ArrayList<ICertificate>();
        for (BaseCertificateInfo item : listCert) {
            ICertificate icrt = new Certificate(item, agreementUUID, this);
            listCertificate.add(icrt);
        }
        System.out.println("err code: " + signCloudResp.error);
        System.out.println("error description: " + signCloudResp.errorDescription);
        return listCertificate;
    }

}
