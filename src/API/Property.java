package API;

import java.util.Base64;

public class Property {

    public String baseUrl;
    public String relyingParty;
    public String relyingPartyUser;
    public String relyingPartyPassword;
    public String relyingPartySignature;
    public String relyingPartyKeyStore;
    public String relyingPartyKeyStorePassword;

    public Property(String baseUrl,
            String relyingParty,
            String relyingPartyUser,
            String relyingPartyPassword,
            String relyingPartySignature,
            String relyingPartyKeyStore,
            String relyingPartyKeyStorePassword) {

        this.baseUrl = baseUrl;
        this.relyingParty = relyingParty;
        this.relyingPartyUser = relyingPartyUser;
        this.relyingPartyPassword = relyingPartyPassword;
        this.relyingPartySignature = relyingPartySignature;
        this.relyingPartyKeyStore = relyingPartyKeyStore;
        this.relyingPartyKeyStorePassword = relyingPartyKeyStorePassword;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getRelyingParty() {
        return relyingParty;
    }

    public void setRelyingParty(String relyingParty) {
        this.relyingParty = relyingParty;
    }

    public String getRelyingPartyUser() {
        return relyingPartyUser;
    }

    public void setRelyingPartyUser(String relyingPartyUser) {
        this.relyingPartyUser = relyingPartyUser;
    }

    public String getRelyingPartyPassword() {
        return relyingPartyPassword;
    }

    public void setRelyingPartyPassword(String relyingPartyPassword) {
        this.relyingPartyPassword = relyingPartyPassword;
    }

    public String getRelyingPartySignature() {
        return relyingPartySignature;
    }

    public void setRelyingPartySignature(String relyingPartySignature) {
        this.relyingPartySignature = relyingPartySignature;
    }

    public String getRelyingPartyKeyStore() {
        return relyingPartyKeyStore;
    }

    public void setRelyingPartyKeyStore(String relyingPartyKeyStore) {
        this.relyingPartyKeyStore = relyingPartyKeyStore;
    }

    public String getRelyingPartyKeyStorePassword() {
        return relyingPartyKeyStorePassword;
    }

    public void setRelyingPartyKeyStorePassword(String relyingPartyKeyStorePassword) {
        this.relyingPartyKeyStorePassword = relyingPartyKeyStorePassword;
    }

    public String getAuthorization() throws Exception {
        String timestamp = String.valueOf(System.currentTimeMillis());
        String data2sign = relyingPartyUser + relyingPartyPassword + relyingPartySignature + timestamp;
        String pkcs1Signature = Utils.getPKCS1Signature(data2sign, relyingPartyKeyStore, relyingPartyKeyStorePassword);

        String strSSL2 = (relyingPartyUser + ":" + relyingPartyPassword + ":" + relyingPartySignature + ":" + timestamp + ":" + pkcs1Signature);
        byte[] byteSSL2 = strSSL2.getBytes();

        return "SSL2 " + Base64.getEncoder().encodeToString(byteSSL2);
    }

    public String getAuthorization(String username, String password) throws Exception {
        String timestamp = String.valueOf(System.currentTimeMillis());
        String data2sign = relyingPartyUser + relyingPartyPassword + relyingPartySignature + timestamp;
        String pkcs1Signature = Utils.getPKCS1Signature(data2sign, relyingPartyKeyStore, relyingPartyKeyStorePassword);

        String strSSL2 = (relyingPartyUser + ":" + relyingPartyPassword + ":" + relyingPartySignature + ":" + timestamp + ":" + pkcs1Signature);
        String basic = "USERNAME:" + username + ":" + password;
        byte[] basicBytes = basic.getBytes();
        byte[] byteSSL2 = strSSL2.getBytes();

        return "SSL2 " + Base64.getEncoder().encodeToString(byteSSL2) + ", Basic " + Base64.getEncoder().encodeToString(basicBytes);
    }

}
