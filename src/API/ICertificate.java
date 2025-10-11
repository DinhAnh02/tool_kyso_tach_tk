package API;

import Model.Request.DocumentDigests;
import Model.Enum.SignAlgo;
import Model.Enum.SignedPropertyType;
import Model.Enum.MobileDisplayTemplate;
import Model.Response.BaseCertificateInfo;
import java.util.HashMap;
import java.util.List;
import Model.Response.CertificateInfo;

public interface ICertificate {

    BaseCertificateInfo baseCredentialInfo() throws Exception;

    //getCredentialInfo();
    CertificateInfo credentialInfo() throws Exception;

    CertificateInfo credentialInfo(String cetificate, boolean certInfoEnabled, boolean authInfoEnabled) throws Exception;

    //authorize
    //if certififate has auth_mode
    //          - PIN then authorizeCode is pin-code
    //          - OTP then authorizeCode is otp
    //          - TSE then authorizeCode is null
    //validIn in seconds
    String authorize(int numSignatures, DocumentDigests doc, SignAlgo signAlgo, String authorizeCode) throws Throwable;

    String authorize(int numSignatures, DocumentDigests doc, SignAlgo signAlgo, String otpRequestID, String otp) throws Throwable;

    String authorize(int numSignatures, DocumentDigests doc, SignAlgo signAlgo, MobileDisplayTemplate displayTemplate) throws Throwable;

    //if DocumentDigests/SignAlgo is avaiable in authorize then they can missing
    List<byte[]> signHash(String credentialID, DocumentDigests documentDigest, SignAlgo signAlgo, String SAD) throws Exception;

    //sign document, now support sign pdf file
    List<byte[]> signDoc(HashMap<SignedPropertyType, Object> signedProps, List<byte[]> docs, String SAD) ;
}
