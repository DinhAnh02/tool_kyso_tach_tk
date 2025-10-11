package restful.sdk.Demo;

import Model.Enum.HashAlgorithmOID;
import Model.Enum.SignAlgo;
import Model.Request.DocumentDigests;
import Model.Response.BaseCertificateInfo;
import Model.SessionFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Properties;
import API.ICertificate;
import API.IServerSession;
import API.Property;
import API.Utils;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Scanner;
import vn.mobileid.openpdf.ImageAligment;
import vn.mobileid.openpdf.PDFSignObject;
import vn.mobileid.openpdf.PDFSigner;
import vn.mobileid.openpdf.PDFSignerResult;
import vn.mobileid.openpdf.Rectangle;
import vn.mobileid.openpdf.SignatureImage;
import vn.mobileid.openpdf.TextAlignment;
import java.nio.file.Paths;

public class MainDemo {
    
    public static List<Certificate> certChain = new ArrayList<>(); 
    public static String PATH_TO_FILE_CONFIG = Paths.get("file", "DAKLAK_DEMO.ssl2").toString();  //PAPERLESS
    public static String credentialID = null;
    public static String sad;

    public static SignAlgo signAlgo = SignAlgo.RSA;
    public static HashAlgorithmOID hashAlgo = HashAlgorithmOID.SHA_256;
    public static Properties prop = new Properties();
    public static IServerSession session;
    public static ICertificate crt;
    public static String cert;

    public static String cert_CA = "MIIEtTCCA52gAwIBAgIMESmsIxjsUoc6VXuEMA0GCSqGSIb3DQEBBQUAMG4xJDAi\n"
            + "BgNVBAMMG0ZQVCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEfMB0GA1UECwwWRlBU\n"
            + "IEluZm9ybWF0aW9uIFN5c3RlbTEYMBYGA1UECgwPRlBUIENvcnBvcmF0aW9uMQsw\n"
            + "CQYDVQQGEwJWTjAeFw0yNTAzMjYwODIxMjhaFw0yNTA0MjUwODIxMjhaMGExCzAJ\n"
            + "BgNVBAYTAlZOMRcwFQYDVQQIDA5I4buSIENIw40gTUlOSDEYMBYGA1UEAwwPTmd1\n"
            + "eeG7hW4gVsSDbiBBMR8wHQYKCZImiZPyLGQBAQwPQ0NDRDoxMjM0NTY3ODkwMIIB\n"
            + "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA39W/JQhN0W1VKAN6V24k++0j\n"
            + "AxcIB2GcwX7oQ0YB5GCrfeSa4frX6esWV39uijwV0L1nU/CrkTh5VH7tKuN7kQte\n"
            + "aVvg1fBne3WrI+3Q58/j00yLS6/Oga5turY94+TUiiLIaL9y8h2sFTVIOVzpE5Tb\n"
            + "fhFgd7y48ntoLaPEdrwe3bWDV5fCYJ32HMYdYNUc5tgB/jreUCdl5uPKOCUgEjwI\n"
            + "VZt78yxvsRXGpzlC0JPHGJel/+uVrMwe7TeWchAWKpQfk4+WwYLyk77EvbQHfu/r\n"
            + "tM7si6JO8trl6TN7/jc9ryCt6R3aIq763JuXXdoJE5ypZs+6oDx+U7IcYbeGzwID\n"
            + "AQABo4IBXjCCAVowDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQZzArNe5kvU8Am\n"
            + "+hXpXTmCQlR8DzA+BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHA6Ly9t\n"
            + "b2JpbGUtaWQudm4vb2NzcC9yZXNwb25kZXIwRQYDVR0gBD4wPDA6BgsrBgEEAYHt\n"
            + "AwEEATArMCkGCCsGAQUFBwIBFh1odHRwczovL21vYmlsZS1pZC52bi9jcHMuaHRt\n"
            + "bDA0BgNVHSUELTArBggrBgEFBQcDAgYIKwYBBQUHAwQGCisGAQQBgjcKAwwGCSqG\n"
            + "SIb3LwEBBTA9BgNVHR8ENjA0MDKgMKAuhixodHRwOi8vbW9iaWxlLWlkLnZuL2Ny\n"
            + "bC9nZXQ/bmFtZT1GUFRfQ0FfU0hBMTAdBgNVHQ4EFgQUsvrShE4VnVTCkKWH8knr\n"
            + "TFj8S98wDgYDVR0PAQH/BAQDAgTwMA0GCSqGSIb3DQEBBQUAA4IBAQB4JaA18pyX\n"
            + "C9s649yU8wTrqXsaj7KbFWcRnNUxsiZjEQuZYEaC958m1mXdx1PHljUqGBtx9BWv\n"
            + "FixC3bf4VIA2mxVWZ+QwF0TiUVknPMZcsxB1So25yIckK5tLtkRvzzoM1fpG/Ikc\n"
            + "zcOWw2MbMNdyluBuMQCGZQ7G6c+9bSxlcQnMJOUiGprProwpHPOdeFGkHhR0JSCM\n"
            + "kGFQo07yBGgtaS1gsFf8cSyOiRlXO9x7pz3wmmXL/7dteuWEv0Io0qrGa6tfjom1\n"
            + "iotndfCA+KLz8AfUD885+qntejpzStUK9Aoezbzw5pQTtHqv94xmNAlHau2sPTr0\n"
            + "YuifpwThTv61";
    public static String cert_Root = "MIID6TCCAtGgAwIBAgIQVBBSesIo0n5SXiud4r01PzANBgkqhkiG9w0BAQUFADB+MR0wGwYDVQQDDBRNSUMgTmF0aW9uYWwgUm9vdCBDQTEbMBkGA1UECwwSTmF0aW9uYWwgQ0EgQ2VudGVyMTMwMQYDVQQKDCpNaW5pc3RyeSBvZiBJbmZvcm1hdGlvbiBhbmQgQ29tbXVuaWNhdGlvbnMxCzAJBgNVBAYTAlZOMB4XDTE5MDYwNDA4MjAwOFoXDTI5MDYwNDA4MjAwOFowfjEdMBsGA1UEAwwUTUlDIE5hdGlvbmFsIFJvb3QgQ0ExGzAZBgNVBAsMEk5hdGlvbmFsIENBIENlbnRlcjEzMDEGA1UECgwqTWluaXN0cnkgb2YgSW5mb3JtYXRpb24gYW5kIENvbW11bmljYXRpb25zMQswCQYDVQQGEwJWTjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJr1tm6iDDtvs0HtFLksjBiCMAdu0XNgeQ1s7QT2tYvLM4S6FDtQryZ+HGEh9pI04IQ0bJ7DNM1F6N583mPxpcFgG0a5QXpyuJMcDOQ0+ih+KH2mgzmEeFN9HrL6HA0h/x7p7kyAprKRsaNdclNq8lVcxaJqBy2DRFptjhGErntbZQKP80vqiKwLIHi+xOddpI1mEGnB4D9NItbQz+1vKLHCtB20ywsJ30GMcu162T+PSM2PpK9u+U25ZrcfLa2EmBW0tiMmZuQl4PTyGmoPmup8K6THrt57XHHgRoA2svyDOWUuMCVABE5K31IHN3oWEOmJViry/lae+PYy7KV00y0CAwEAAaNjMGEwHQYDVR0OBBYEFO2qtcbfOrjXTp38PVx+RGsW6/wgMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU7aq1xt86uNdOnfw9XH5Eaxbr/CAwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBBQUAA4IBAQCa3YjUBCFs9oTSovWxxY1Gd6hYMkUrPFeDX45K6LfIEMN8iotisF+Ss+zHe+rWF5mDA53547x3wdkJFxAEmTHwu5OXZbWfbtXQPu4b0CBFt53XamAyAv4MUqzFpgzCNj8dMD4WHHqlXd1++YcpN5+QAMW6ARqfgnYLItGtzm2tF9WmV51I6Zfbo4tfr9JY/9UlrgfjfTgnxZvXknQIwz9D7xgND9gUhPPkn6J/jW3H9r57ZxknoLty3MJOu3cwOljoEOhWWleN/iGrw7VIJc5U5BD3hsYHUITl0aSsJ5+7ikBDKs2EGTCduv97T4nlWOhV/JST6m8DynwYbChgwylt";

    public static void main(String[] args) throws IOException, Exception, Throwable {

        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        int resultCode = 0;



        while (true) {
            try {
                printUsage(reader);
                System.out.print("\nEnter the function: ");
                resultCode = Integer.parseInt(reader.readLine());

                switch (resultCode) {

                    case 1:
                        // Logic đăng nhập đã được chuyển vào printUsage khi session is null.
                        // Case 1 bây giờ có thể chỉ đơn giản là refresh lại menu.
                        if (session != null) {
                            System.out.println("Bạn đã đăng nhập.");
                        }
                        // Nếu session là null, printUsage sẽ tự động hỏi thông tin đăng nhập.
                        break;
                    case 2:
                        List<ICertificate> listCert = session.listCertificates();
                        for (ICertificate item : listCert) {
                            BaseCertificateInfo bci = item.baseCredentialInfo();
                            System.out.println("Identity of certificate          : " + bci.getCredentialID());
                            System.out.println("Status of certificate            : " + bci.getStatus());
                            System.out.println("Description status of certificate: " + bci.getStatusDesc());
                        }
                        break;

                    case 3: //credentials/info
                        Scanner scanner = new Scanner(System.in);
                        System.out.print("Nhập credentialID: ");
                        credentialID = scanner.nextLine();
                        crt = session.certificateInfo(credentialID);
                        BaseCertificateInfo info = crt.baseCredentialInfo();
                        cert = info.getCertificates()[0];
                        System.out.println("certificates: " + cert);
                        break;

                    case 4: //credentials/authorize
                        DocumentDigests doc;
                        doc = new DocumentDigests();
                        doc.hashAlgorithmOID = HashAlgorithmOID.SHA_256;
                        doc.hashes = new ArrayList<>();

                        //Do authorize for certificate with AuthMode is PIN, we call credentials/authorize
                        Scanner scanner1 = new Scanner(System.in);
                        System.out.print("Nhập Number Signature: ");
                        int numSignatures = scanner1.nextInt();
                        scanner1.nextLine(); // consume newline
                        System.out.print("Nhập mã ủy quyền (authorizeCode): ");
                        String authorizeCode = scanner1.nextLine();
                        sad = crt.authorize(numSignatures, doc, null, authorizeCode);
                        System.out.println("SAD: " + sad);
                        break;

                    case 5: // signature/signHash
                        try {
                        long startTime = System.currentTimeMillis();

                        byte[] filePdf = Files.readAllBytes(new File("file/test.pdf").toPath());
                        byte[] filePdf1 = Files.readAllBytes(new File("file/test1.pdf").toPath());

                        certChain = new ArrayList<>();
                        certChain.add(decodeCertificate(cert));
                        certChain.add(decodeCertificate(cert_CA));
                        certChain.add(decodeCertificate(cert_Root));

                        List<PDFSignObject> dataToBeSigns = new ArrayList<>();
                        PDFSignObject pdf = new PDFSignObject();

                        Date now = new Date();

                        SimpleDateFormat formatter = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
                        String formattedDate = formatter.format(now);

                        pdf.setDocument(filePdf);
                        pdf.setPageNo("1");
                        pdf.setRectangle(new Rectangle(100, 100, 300, 200));
                        pdf.setPositionStringIdentifier("Digital_Signature");
                        pdf.setFontSize((float) 12.5);
                        pdf.setReason("test12345");
                        pdf.setLocation("HN");
                        pdf.setVisibleValidationSymbol(Boolean.FALSE);
                        pdf.setSigningTime(now);
                        pdf.setDateFormat(formattedDate);
//                    pdf.setSignerInformation("Ký bởi: " + personalName
//                            + "\nLý do: " + signer1.getReason()
//                            + "\nKý ngày: " + formattedDate
//                            + "\nNơi ký: " + signer1.getLocation());

                        pdf.setSignerInformation("Ký bởi: {signby}"
                                + "\nLý do: {reason}"
                                + "\nKý ngày: {date}"
                                + "\nNơi ký: {location}");
                        pdf.setTextAligment(TextAlignment.LEFT_TOP);
                        pdf.setTextPaddingLeft(0);
                        pdf.setTextPaddingRight(0);
                        pdf.setPlaceAll(Boolean.FALSE);

                        byte[] imageData = Files.readAllBytes(new File("file/signature.png").toPath());
                        SignatureImage signatureImage = new SignatureImage(imageData);
                        signatureImage.setImageAligment(ImageAligment.RIGHT_BOTTOM);
                        signatureImage.scaleToFit(50, 50);
                        pdf.setSignatureImage(signatureImage);
                        dataToBeSigns.add(pdf);

                        PDFSignObject pdf1 = new PDFSignObject();
                        pdf1.setDocument(filePdf1);
                        pdf1.setPageNo("1");
                        pdf1.setPositionStringIdentifier("Digital_Signature");
                        Rectangle.Offset offset = new Rectangle.Offset(0, -100);
                        pdf1.setRectangle(new Rectangle(200, 100, offset));

                        pdf1.setFontSize((float) 11);
                        pdf1.setReason("test");
                        pdf1.setLocation("HCM");
                        pdf1.setVisibleValidationSymbol(Boolean.FALSE);
                        pdf1.setSigningTime(now);
                        pdf1.setDateFormat(formattedDate);
                        pdf1.setSignerInformation("Ký bởi: {signby}"
                                + "\nLý do: {reason}"
                                + "\nKý ngày: {date}"
                                + "\nNơi ký: {location}");
                        pdf1.setTextAligment(TextAlignment.LEFT_TOP);
                        pdf1.setTextPaddingLeft(50);
                        pdf1.setTextPaddingRight(0);
                        pdf1.setPlaceAll(Boolean.FALSE);

                        byte[] imageData1 = Files.readAllBytes(new File("file/signature.png").toPath());
                        SignatureImage signatureImage1 = new SignatureImage(imageData1);
                        signatureImage1.setImageAligment(ImageAligment.RIGHT_BOTTOM);
                        signatureImage1.scaleToFit(50, 50);
                        pdf1.setSignatureImage(signatureImage1);
                        dataToBeSigns.add(pdf1);

                        PDFSigner signer = new PDFSigner();
                        PDFSignerResult pdfSignerResult = signer.initSign(dataToBeSigns, certChain);

                        long endTime = System.currentTimeMillis();
                        long timeElapsed = endTime - startTime;
                        System.out.println("timeElapsed: " + timeElapsed);

                        List<byte[]> hashList = pdfSignerResult.getHashesList();
                        List<String> hashes = new ArrayList<>();
                        for (byte[] h : hashList) {
                            System.out.println("h: " + Base64.getEncoder().encodeToString(h));
                            hashes.add(Base64.getEncoder().encodeToString(h));
                        }
                        
                            DocumentDigests Doc = new DocumentDigests();
                        Doc.hashAlgorithmOID = hashAlgo;
                        Doc.hashes = new ArrayList<>();
                        for (int i = 0; i < hashes.size(); i++){
                            Doc.hashes.add(Utils.base64Decode(hashes.get(i)));

                        }

                        List<byte[]> signatures = crt.signHash(credentialID, Doc, signAlgo, sad);

                        PDFSignerResult finalSign = finalSign(pdfSignerResult.getTemporalDatas(), signatures);
                        List<byte[]> signedDocs = finalSign.getSignedDocuments();

                        for (int i = 0; i < signedDocs.size(); i++) {
                            String signedFile = "file/finalSign/sample_" + i + ".signed.pdf";
                            try (FileOutputStream fos = new FileOutputStream(signedFile)) {
                                fos.write(signedDocs.get(i));
                                System.out.println("Đã lưu file PDF đã ký vào: " + signedFile);
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                    } catch (IOException e) {
                        System.err.println(e.getMessage());
                    }
                    break;

                    default:
                        break;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private static void printUsage(BufferedReader reader) throws IOException {
        System.out.println("\n========== RESTFUL SDK FUNCTIONS =========");
        System.out.println("1. auth/login");
        System.out.println("2. credentials/list");
        System.out.println("3. credentials/info");
        System.out.println("4. credentials/authorize");
        System.out.println("5. signatures/signHash");
        if (session == null) {
            System.out.print("Chưa đăng nhập. Nhập username: ");
            String username = reader.readLine();
            System.out.print("Nhập password: ");
            String password = reader.readLine();
            try {
                Handshake_func(username, password);
            } catch (Exception e) {
                System.out.println("Đăng nhập thất bại: " + e.getMessage());
            }
        }
    }

    public static IServerSession Handshake_func(String username, String password) throws IOException {

        File file = new File(PATH_TO_FILE_CONFIG);
        InputStream stream = new FileInputStream(file);

        if (stream == null) {
            System.out.println("Can read config-file: [" + file + "]");
        }
        try (final InputStreamReader in = new InputStreamReader(stream, StandardCharsets.UTF_8)) {
            prop.load(in);
        }
        if (prop.keySet() == null) {
            System.out.println("Not found keys in [" + file + "]");
        }

        String baseUrl = prop.getProperty("mobileid.rssp.baseurl");
        String relyingParty = prop.getProperty("mobileid.rssp.rp.name");
        String relyingPartyUser = prop.getProperty("mobileid.rssp.rp.user");
        String relyingPartyPassword = prop.getProperty("mobileid.rssp.rp.password");
        String relyingPartySignature = prop.getProperty("mobileid.rssp.rp.signature");
        String relyingPartyKeyStore = prop.getProperty("mobileid.rssp.rp.keystore.file");
        String relyingPartyKeyStorePassword = prop.getProperty("mobileid.rssp.rp.keystore.password");

        Property property = new Property(baseUrl,
                relyingParty,
                relyingPartyUser,
                relyingPartyPassword,
                relyingPartySignature,
                relyingPartyKeyStore,
                relyingPartyKeyStorePassword);

        SessionFactory factory = new SessionFactory(property, "VN", username, password);
        session = factory.getServerSession();
        return session;
    }

    public static String getInputAsString() {
        Scanner s = new Scanner(System.in);
        return s.nextLine();
    }

    public static int getInputAsInt() throws Throwable {
        Scanner s = new Scanner(System.in);
        do {
            try {
                String str = s.nextLine();
                int number = Integer.parseInt(str);
                return number;
            } catch (Exception ex) {
                System.out.print("\nInvalid param, it must be a number: ");
            }
        } while (true);
    }

    public static String getFileAsString(String file) throws Throwable {
        InputStream inStream = new FileInputStream(file);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert2 = (X509Certificate) cf.generateCertificate(inStream);
        return Utils.base64Encode(cert2.getEncoded());
    }

    private static Certificate decodeCertificate(String base64Cert) throws Exception {
        byte[] decoded = Base64.getMimeDecoder().decode(base64Cert);

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return certFactory.generateCertificate(new ByteArrayInputStream(decoded));
    }

    private static PDFSignerResult finalSign(List<byte[]> temporalData, List<byte[]> signatures) throws Exception {
        PDFSigner signer = new PDFSigner();
        return signer.finalSign(temporalData, signatures);
    }
    public static void login(String username, String password) throws Exception {
        // This method now establishes a session with the provided credentials.
        if (session == null) {
            Handshake_func(username, password);
        }
        session.login(); // Re-login if needed, or establish new session
    }

    public static String getFirstCredentialId() throws Exception {
        if (session != null) {
            List<ICertificate> listCert = session.listCertificates();
            if (!listCert.isEmpty()) {
                return listCert.get(0).baseCredentialInfo().getCredentialID();
            }
        }
        return null;
    }

    public static ICertificate getCertificate(String credentialID) throws Exception {
        if (session != null) {
            return session.certificateInfo(credentialID);
        }
        return null;
    }

    public static List<Certificate> getCertificateChain(String credentialID) throws Exception {
        if (crt != null) {
            // Giả sử crt có phương thức lấy chuỗi chứng chỉ, nếu không, sử dụng certChain đã khởi tạo
            return certChain; // Hoặc điều chỉnh nếu có phương thức cụ thể từ crt
        }
        return null;
    }
}