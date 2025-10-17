package restful.sdk.Demo;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import Model.Request.DocumentDigests;
import API.ICertificate;
import Model.Response.BaseCertificateInfo;
import vn.mobileid.openpdf.ImageAligment;
import vn.mobileid.openpdf.PDFSignObject;
import vn.mobileid.openpdf.PDFSigner;
import vn.mobileid.openpdf.PDFSignerResult;
import vn.mobileid.openpdf.Rectangle;
import vn.mobileid.openpdf.SignatureImage;

public class SignServer {

    // Global state for the logged-in user.
    // WARNING: This simple implementation only supports one user session at a time.
    private static String credentialID;
    private static String authorizeCode;
    private static List<Certificate> certChain;
    private static ICertificate crt;

    // Nếu bạn có chuỗi base64 đầy đủ của CA/Root thì mới gán vào đây
    private static final String cert_CA = null;
    private static final String cert_Root = null;

    private static Certificate decodeCertificate(String base64Cert) throws Exception {
        if (base64Cert == null || base64Cert.trim().isEmpty()) {
            return null;
        }
        byte[] decoded = Base64.getMimeDecoder().decode(base64Cert);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return certFactory.generateCertificate(new ByteArrayInputStream(decoded));
    }

    public static void main(String[] args) throws Exception {
        // Xóa bỏ hoàn toàn việc đăng nhập lúc khởi động.
        // Server sẽ chỉ bắt đầu và chờ yêu cầu từ client.
        // Quá trình đăng nhập sẽ được xử lý trong SignHandler cho mỗi yêu cầu.

        HttpServer server = HttpServer.create(new InetSocketAddress(8081), 0);
        server.createContext("/login", new LoginHandler());
        server.createContext("/sign", new SignHandler());
        server.createContext("/cert-info", new CertInfoHandler());
        server.setExecutor(null);
        server.start();

        System.out.println("SignServer running at:");
        System.out.println("   POST http://localhost:8081/login");
        System.out.println("   POST http://localhost:8081/sign");
        System.out.println("   GET  http://localhost:8081/cert-info");
    }

    static class CertInfoHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }

                // This handler now provides info for the *last* user who signed,
                // or the demo user if no one has signed yet.
                // For a multi-user environment, you might want to change this logic.
                if (credentialID == null || crt == null) {
                     throw new IllegalStateException("Chưa có người dùng nào đăng nhập. Vui lòng gọi API /login trước.");
                }

                BaseCertificateInfo info = crt.baseCredentialInfo();
                String userCert = info.getCertificates()[0];
                Certificate userCertificate = decodeCertificate(userCert);
                java.security.cert.X509Certificate x509 = (java.security.cert.X509Certificate) userCertificate;

                SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
                String json = "{"
                        + "\"credentialId\": \"" + credentialID + "\","
                        + "\"subject\": \"" + x509.getSubjectDN() + "\","
                        + "\"issuer\": \"" + x509.getIssuerDN() + "\","
                        + "\"validFrom\": \"" + sdf.format(x509.getNotBefore()) + "\","
                        + "\"validTo\": \"" + sdf.format(x509.getNotAfter()) + "\""
                        + "}";

                exchange.getResponseHeaders().add("Content-Type", "application/json; charset=UTF-8");
                exchange.sendResponseHeaders(200, json.getBytes().length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(json.getBytes());
                }
            } catch (Exception e) {
                String msg = "{\"error\":\"" + e.getMessage() + "\"}";
                exchange.sendResponseHeaders(500, msg.getBytes().length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(msg.getBytes());
                }
            }
        }
    }

    static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                    return;
                }

                System.out.println("== Bat dau nhan request dang nhap ==");

                // Read and parse JSON request body
                InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), "utf-8");
                Gson gson = new Gson();
                LoginRequest loginRequest = gson.fromJson(isr, LoginRequest.class);

                if (loginRequest == null || loginRequest.username == null || loginRequest.password == null || loginRequest.authorizeCode == null) {
                    throw new IllegalArgumentException("Yêu cầu không hợp lệ. Cần có: username, password, authorizeCode.");
                }

                // Step 1: Login
                MainDemo.login(loginRequest.username, loginRequest.password);
                System.out.println("Đăng nhập thành công cho user: " + loginRequest.username);

                // Step 2: Get credential and certificate info
                String credID = MainDemo.getFirstCredentialId();
                if (credID == null) {
                    throw new RuntimeException("Không tìm thấy credential nào cho user: " + loginRequest.username);
                }

                // Step 3: Store session state globally
                SignServer.credentialID = credID;
                SignServer.authorizeCode = loginRequest.authorizeCode;
                SignServer.crt = MainDemo.getCertificate(credID);

                BaseCertificateInfo info = crt.baseCredentialInfo();
                String userCert = info.getCertificates()[0];

                Certificate userCertificate = decodeCertificate(userCert);
                if (userCertificate == null) {
                    throw new RuntimeException("User certificate null hoặc decode thất bại!");
                }

                SignServer.certChain = new ArrayList<>();
                SignServer.certChain.add(userCertificate);
                Certificate caCert = decodeCertificate(cert_CA);
                if (caCert != null) SignServer.certChain.add(caCert);
                Certificate rootCert = decodeCertificate(cert_Root);
                if (rootCert != null) SignServer.certChain.add(rootCert);

                System.out.println("Đã lấy và lưu thông tin chứng thư cho credentialID: " + credID);

                // Step 4: Send success response
                String jsonResponse = "{\"status\":\"success\", \"message\":\"Đăng nhập và khởi tạo chứng thư thành công.\", \"credentialId\":\"" + credID + "\"}";
                exchange.getResponseHeaders().add("Content-Type", "application/json; charset=UTF-8");
                exchange.sendResponseHeaders(200, jsonResponse.getBytes("UTF-8").length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(jsonResponse.getBytes("UTF-8"));
                }
                System.out.println("== Ket thuc qua trinh dang nhap ==");

            } catch (Exception e) {
                handleError(e, exchange);
            }
        }
    }

    static class SignHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }

                System.out.println("== Bat dau nhan request ky so ==");

                // Check if user is logged in
                if (credentialID == null || crt == null || certChain == null || authorizeCode == null) {
                    throw new IllegalStateException("Chưa đăng nhập hoặc thông tin phiên chưa đầy đủ. Vui lòng gọi API /login trước.");
                }

                // Khai báo các biến để lưu thông tin ký
                byte[] inputPdf;
                byte[] signatureImgBytes;
                Rectangle signatureRectangle;
                String pageNo;

                String contentType = exchange.getRequestHeaders().getFirst("Content-Type");

                if (contentType != null && contentType.toLowerCase().contains("application/json")) {
                    System.out.println("Nhan yeu cau ky so qua JSON");
                    // Xử lý request JSON
                    InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), "utf-8");
                    Gson gson = new Gson();
                    SignRequest signRequest = gson.fromJson(isr, SignRequest.class);

                    if (signRequest == null || signRequest.pdfData == null || signRequest.pdfData.isEmpty()) {
                        throw new IllegalArgumentException("Yêu cầu JSON không hợp lệ. Cần có 'pdfData' (base64).");
                    }

                    inputPdf = Base64.getDecoder().decode(signRequest.pdfData);

                    // Lấy ảnh chữ ký từ request, nếu không có thì dùng ảnh mặc định
                    if (signRequest.signatureImage != null && !signRequest.signatureImage.isEmpty()) {
                        signatureImgBytes = Base64.getDecoder().decode(signRequest.signatureImage);
                        System.out.println("Da load anh chu ky tu request JSON");
                    } else {
                        signatureImgBytes = Files.readAllBytes(Paths.get("file/img_ki_so.jpg"));
                        System.out.println("Su dung anh chu ky mac dinh");
                    }

                    // Lấy tọa độ từ request, nếu không có thì dùng tọa độ mặc định
                    if (signRequest.signaturePlacement != null) {
                        SignRequest.SignaturePlacement p = signRequest.signaturePlacement;
                        signatureRectangle = new Rectangle(p.x, p.y, p.x + p.width, p.y + p.height);
                        pageNo = String.valueOf(p.page);
                        System.out.println("Da lay toa do tu request JSON cho trang " + pageNo);
                    } else {
                        signatureRectangle = new Rectangle(100, 100, 350, 220);
                        pageNo = "1";
                        System.out.println("Su dung toa do mac dinh");
                    }
                } else {
                    System.out.println("Nhan yeu cau ky so voi file PDF tho (khong co anh chu ky)");
                    // Xử lý request PDF thô (giữ nguyên logic cũ)
                    InputStream is = exchange.getRequestBody();
                    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                    byte[] data = new byte[4096];
                    int nRead;
                    while ((nRead = is.read(data, 0, data.length)) != -1) {
                        buffer.write(data, 0, nRead);
                    }
                    inputPdf = buffer.toByteArray();
                    // Sử dụng các giá trị mặc định
                    signatureImgBytes = null;
                    signatureRectangle = new Rectangle(100, 100, 350, 220);
                    pageNo = "1";
                }

                if (inputPdf.length == 0) {
                    throw new RuntimeException("Khong nhan duoc du lieu PDF tu request");
                }
                System.out.println("Da nhan du lieu PDF co kich thuoc: " + inputPdf.length + " bytes");

                // Tao doi tuong PDFSignObject
                PDFSignObject pdfObj = new PDFSignObject();
                pdfObj.setDocument(inputPdf);
                pdfObj.setPageNo(pageNo);
                pdfObj.setRectangle(signatureRectangle);
                pdfObj.setFontSize(12.5f);
                pdfObj.setReason("Ký Số");
                pdfObj.setLocation("Ha Noi");
                pdfObj.setVisibleValidationSymbol(Boolean.FALSE);

                Date now = new Date();
                SimpleDateFormat formatter = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
                pdfObj.setSigningTime(now);
                pdfObj.setDateFormat(formatter.format(now));
                pdfObj.setSignerInformation("Ký bởi: {signby}\nLý do: {reason}\nNgày ký: {date}\nNơi ký: {location}");

                // Chỉ thêm ảnh nếu nó tồn tại (được gửi qua JSON)
                if (signatureImgBytes != null && signatureImgBytes.length > 0) {
                    SignatureImage sigImg = new SignatureImage(signatureImgBytes);
                    sigImg.scaleToFit(150, 60);
                    sigImg.setImageAligment(ImageAligment.RIGHT_BOTTOM);
                    pdfObj.setSignatureImage(sigImg);
                }

                List<PDFSignObject> dataToBeSigns = new ArrayList<>();
                dataToBeSigns.add(pdfObj);
                System.out.println("Da tao doi tuong PDFSignObject thanh cong");

                // Khoi tao signer
                PDFSigner pdfSigner = new PDFSigner();
                if (certChain == null || certChain.isEmpty()) {
                    throw new RuntimeException("Certificate chain rong! Can khoi tao lai certificate");
                }
                System.out.println("Da khoi tao PDFSigner va co san certificate chain");

                // Tao hash
                PDFSignerResult pdfSignerResult = pdfSigner.initSign(dataToBeSigns, certChain);
                List<byte[]> hashList = pdfSignerResult.getHashesList();
                if (hashList == null || hashList.isEmpty()) {
                    throw new RuntimeException("Khong tao duoc hash de authorize/sign");
                }
                System.out.println("Da tao hash thanh cong, so luong: " + hashList.size());

                // Goi authorize
                DocumentDigests doc = new DocumentDigests();
                doc.hashAlgorithmOID = MainDemo.hashAlgo;
                doc.hashes = new ArrayList<>(hashList);
                String sad = crt.authorize(hashList.size(), doc, null, authorizeCode);
                if (sad == null || sad.trim().isEmpty()) {
                    throw new RuntimeException("Authorize that bai (khong co SAD)");
                }
                System.out.println("Authorize thanh cong, nhan duoc SAD");

                // Thuc hien ky hash
                List<byte[]> signatures = crt.signHash(
                        credentialID,
                        doc,
                        MainDemo.signAlgo,
                        sad
                );
                if (signatures == null || signatures.isEmpty()) {
                    throw new RuntimeException("signHash tra ve rong");
                }
                System.out.println("Da ky hash thanh cong, so chu ky: " + signatures.size());

                // Ghep chu ky vao tai lieu
                PDFSignerResult finalResult = pdfSigner.finalSign(
                        pdfSignerResult.getTemporalDatas(),
                        signatures
                );
                List<byte[]> signedDocs = finalResult.getSignedDocuments();
                if (signedDocs == null || signedDocs.isEmpty()) {
                    throw new RuntimeException("finalSign khong tra ve tai lieu da ky");
                }
                System.out.println("Da hoan thanh finalSign va nhan ve tai lieu da ky");

                // Ghi file signed.pdf de debug
                byte[] signedPdf = signedDocs.get(0);
                Path debugFilePath = Paths.get("file", "signed.pdf");
                try {
                    Files.write(debugFilePath, signedPdf);
                    System.out.println("Da luu file debug tai: " + debugFilePath.toAbsolutePath());
                } catch (Exception saveEx) {
                    System.out.println("Khong the luu file debug: " + saveEx.getMessage());
                }

                // Tra ket qua ve client
                exchange.getResponseHeaders().add("Content-Type", "application/pdf");
                exchange.getResponseHeaders().add("Content-Disposition", "attachment; filename=signed.pdf");
                exchange.sendResponseHeaders(200, signedPdf.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(signedPdf);
                }
                System.out.println("Da tra ve file PDF da ky cho client");
                System.out.println("== Ket thuc qua trinh ky so ==");

            } catch (Exception e) {
                handleError(e, exchange);
            } catch (Throwable ex) {
                Logger.getLogger(SignServer.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    // Lớp nội tĩnh để đại diện cho request ký dạng JSON
    static class SignRequest {
        String pdfData; // Dữ liệu PDF dưới dạng Base64
        SignaturePlacement signaturePlacement; // Tọa độ và trang ký (tùy chọn)
        String signatureImage; // Ảnh chữ ký dưới dạng Base64 (tùy chọn)

        static class SignaturePlacement {
            int page = 1; // Mặc định là trang 1
            float x;
            float y;
            float width;
            float height;
        }
    }

    private static void handleError(Exception e, HttpExchange exchange) throws IOException {
        e.printStackTrace();
        String errorMessage = "{\"status\":\"error\", \"message\":\"" + e.getMessage().replace("\"", "'") + "\"}";
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(500, errorMessage.getBytes("UTF-8").length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(errorMessage.getBytes("UTF-8"));
        }
    }
}
