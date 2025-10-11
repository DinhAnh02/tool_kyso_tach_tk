package API;

import Model.Enum.MobileDisplayTemplate;
import Model.Enum.SignAlgo;
import Model.Request.SearchConditions;
import Model.Request.DocumentDigests;
import java.util.List;

public interface IServerSession extends ISession {

    List<ICertificate> listCertificates() throws Exception;

    List<ICertificate> listCertificates(String agreementUUID) throws Exception;

    List<ICertificate> listCertificates(String agreementUUID, String certificate, boolean certInfoEnabled, boolean authInfoEnabled, SearchConditions conditions) throws Exception;

    ICertificate certificateInfo(String credentialID) throws Exception;

    ICertificate certificateInfo(String agreementUUID, String credentialID) throws Exception;

    ICertificate certificateInfo(String agreementUUID, String credentialID, String certificate, boolean certInfoEnabled, boolean authInfoEnabled) throws Exception;

    //authorize
    //if certififate has auth_mode
    //          - PIN then authorizeCode is pin-code
    //          - OTP then authorizeCode is otp
    //          - TSE then authorizeCode is null
    //validIn in seconds
    String authorize(String agreementUUID, String credentialID, int numSignatures, DocumentDigests doc, SignAlgo signAlgo,
            String authorizeCode) throws Throwable;

    String authorize(String agreementUUID, String credentialID, int numSignatures, DocumentDigests doc, SignAlgo signAlgo,
            String otpRequestID, String otp) throws Throwable;

    String authorize(String agreementUUID, String credentialID, int numSignatures, DocumentDigests doc, SignAlgo signAlgo,
            MobileDisplayTemplate displayTemplate) throws Throwable;

    List<byte[]> signHash(String agreementUUID, String credentialID, DocumentDigests documentDigest, SignAlgo signAlgo, String SAD) throws Exception;

}
