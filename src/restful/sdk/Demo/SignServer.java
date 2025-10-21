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
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
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
        server.createContext("/credentials-list", new CredentialsListHandler());
        server.createContext("/select-credential", new SelectCredentialHandler());
        server.createContext("/all-cert-info", new AllCertInfoHandler());
        server.createContext("/cert-info", new CertInfoHandler());
        server.setExecutor(null);
        server.start();

        System.out.println("SignServer running at:");
        System.out.println("   POST http://localhost:8081/select-credential");
        System.out.println("   POST http://localhost:8081/login");
        System.out.println("   POST http://localhost:8081/sign");
        System.out.println("   GET  http://localhost:8081/credentials-list");
        System.out.println("   GET  http://localhost:8081/all-cert-info");
        System.out.println("   GET  http://localhost:8081/cert-info");
    }

    static class AllCertInfoHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                    return;
                }

                if (MainDemo.session == null) {
                    throw new IllegalStateException("Chưa có người dùng nào đăng nhập. Vui lòng gọi API /login trước.");
                }

                // Lấy danh sách credential ID trước
                List<ICertificate> basicCertList = MainDemo.session.listCertificates();
                List<Map<String, Object>> allCertsInfo = new ArrayList<>();

                // Với mỗi credential ID, gọi API để lấy thông tin chi tiết
                for (ICertificate basicCert : basicCertList) {
                    String credId = basicCert.baseCredentialInfo().getCredentialID();
                    try {
                        // Gọi certificateInfo để lấy thông tin đầy đủ
                        ICertificate detailedCert = MainDemo.session.certificateInfo(null, credId, "chain", true, false);
                        if (detailedCert != null) {
                            BaseCertificateInfo info = detailedCert.baseCredentialInfo();
                            Map<String, Object> certMap = new HashMap<>();
                            certMap.put("credentialID", info.getCredentialID());
                            certMap.put("subjectDN", info.getSubjectDN());
                            certMap.put("issuerDN", info.getIssuerDN());
                            certMap.put("validFrom", formatDateString(info.getValidFrom()));
                            certMap.put("validTo", formatDateString(info.getValidTo()));
                            certMap.put("status", info.getStatus());
                            certMap.put("statusDesc", info.getStatusDesc());
                            allCertsInfo.add(certMap);
                        }
                    } catch (Exception certEx) {
                        System.err.println("Không thể lấy thông tin chi tiết cho credentialID: " + credId + ". Lỗi: " + certEx.getMessage());
                        // Có thể bỏ qua hoặc thêm thông tin lỗi vào response
                    }
                }

                Gson gson = new Gson();
                String jsonResponse = gson.toJson(allCertsInfo);

                sendJsonResponse(exchange, 200, jsonResponse);
            } catch (Exception e) {
                handleError(e, exchange);
            }
        }
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
                if (MainDemo.session == null) {
                     throw new IllegalStateException("Chưa có người dùng nào đăng nhập. Vui lòng gọi API /login trước.");
                }

                // Lấy credentialID từ query parameter, ví dụ: /cert-info?credentialID=...
                String query = exchange.getRequestURI().getQuery();
                String credId = Arrays.stream(query.split("&"))
                                      .filter(p -> p.startsWith("credentialID="))
                                      .findFirst()
                                      .map(p -> p.substring("credentialID=".length()))
                                      .orElseThrow(() -> new IllegalArgumentException("Thiếu tham số 'credentialID'"));

                ICertificate certificate = MainDemo.session.certificateInfo(null, credId, "chain", true, false);
                BaseCertificateInfo info = certificate.baseCredentialInfo();

                Map<String, Object> certMap = new HashMap<>();
                certMap.put("credentialID", info.getCredentialID());
                certMap.put("subjectDN", info.getSubjectDN());
                certMap.put("issuerDN", info.getIssuerDN());
                certMap.put("validFrom", formatDateString(info.getValidFrom()));
                certMap.put("validTo", formatDateString(info.getValidTo()));
                certMap.put("status", info.getStatus());

                Gson gson = new Gson();
                String jsonResponse = gson.toJson(certMap);
                sendJsonResponse(exchange, 200, jsonResponse);
            } catch (Exception e) {
                handleError(e, exchange);
            }
        }
    }

    static class CredentialsListHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                    return;
                }

                if (MainDemo.session == null) {
                    throw new IllegalStateException("Chưa có người dùng nào đăng nhập. Vui lòng gọi API /login trước.");
                }

                List<ICertificate> listCert = MainDemo.session.listCertificates();

                List<Map<String, Object>> certListForJson = new ArrayList<>();
                for (ICertificate item : listCert) {
                    BaseCertificateInfo bci = item.baseCredentialInfo();
                    Map<String, Object> certInfo = new LinkedHashMap<>();
                    certInfo.put("credentialID", bci.getCredentialID());
                    certInfo.put("status", bci.getStatus());
                    certInfo.put("statusDesc", bci.getStatusDesc());
                    certListForJson.add(certInfo);
                }

                Gson gson = new Gson();
                String jsonResponse = gson.toJson(certListForJson);

                sendJsonResponse(exchange, 200, jsonResponse);
            } catch (Exception e) {
                handleError(e, exchange);
            } catch (Throwable ex) {
                Logger.getLogger(SignServer.class.getName()).log(Level.SEVERE, null, ex);
                handleError(new Exception(ex), exchange);
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

                // Reset lại các thông tin của phiên cũ
                SignServer.credentialID = null;
                SignServer.crt = null;
                SignServer.certChain = null;

                // Step 2: Store authorizeCode globally for later use
                SignServer.authorizeCode = loginRequest.authorizeCode;
                System.out.println("Đã lưu mã ủy quyền (authorizeCode).");

                // Step 4: Send success response
                String jsonResponse = "{\"status\":\"success\", \"message\":\"Đăng nhập thành công. Vui lòng gọi /select-credential để chọn chứng thư.\"}";
                sendJsonResponse(exchange, 200, jsonResponse);
                System.out.println("== Ket thuc qua trinh dang nhap ==");

            } catch (Exception e) {
                // Nếu đăng nhập thất bại, xóa session cũ để tránh sử dụng lại
                MainDemo.session = null;
                handleError(e, exchange);
            }
        }
    }

    static class SelectCredentialHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                    return;
                }

                if (MainDemo.session == null) {
                    throw new IllegalStateException("Chưa có người dùng nào đăng nhập. Vui lòng gọi API /login trước.");
                }

                InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), "utf-8");
                Gson gson = new Gson();
                SelectCredentialRequest selectRequest = gson.fromJson(isr, SelectCredentialRequest.class);

                if (selectRequest == null || selectRequest.credentialID == null) {
                    throw new IllegalArgumentException("Yêu cầu không hợp lệ. Cần có: credentialID.");
                }

                // Store session state globally
                SignServer.credentialID = selectRequest.credentialID;
                SignServer.crt = MainDemo.getCertificate(selectRequest.credentialID);

                BaseCertificateInfo info = crt.baseCredentialInfo();
                String userCertBase64 = info.getCertificates()[0];

                Certificate userCertificate = decodeCertificate(userCertBase64);
                if (userCertificate == null) throw new RuntimeException("User certificate null hoặc decode thất bại!");

                SignServer.certChain = new ArrayList<>();
                SignServer.certChain.add(userCertificate);
                // Các chứng thư CA và Root sẽ được thêm nếu được cấu hình

                System.out.println("Đã chọn và khởi tạo chứng thư cho credentialID: " + selectRequest.credentialID);

                String jsonResponse = "{\"status\":\"success\", \"message\":\"Đã chọn chứng thư thành công.\", \"credentialId\":\"" + selectRequest.credentialID + "\"}";
                sendJsonResponse(exchange, 200, jsonResponse);
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
        String message = (e.getMessage() == null) ? "Lỗi không xác định" : e.getMessage().replace("\"", "'");
        String errorMessage = "{\"status\":\"error\", \"message\":\"" + message + "\"}";
        sendJsonResponse(exchange, 500, errorMessage);
    }

    private static void sendJsonResponse(HttpExchange exchange, int statusCode, String jsonResponse) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        byte[] responseBytes = jsonResponse.getBytes("UTF-8");
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) { os.write(responseBytes); }
    }

    private static String formatDateString(String dateString) {
        if (dateString == null || dateString.length() != 14) {
            return dateString; // Trả về nguyên bản nếu không đúng định dạng
        }
        try {
            // Định dạng đầu vào từ SDK (yyyyMMddHHmmss) và giả định nó là UTC
            DateTimeFormatter inputFormatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss").withZone(ZoneId.of("UTC"));
            // Định dạng đầu ra mong muốn (dd-MM-yyyy HH:mm:ss)
            DateTimeFormatter outputFormatter = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss");
            // Múi giờ đích (UTC+7)
            ZoneId targetZone = ZoneId.of("Asia/Ho_Chi_Minh");

            ZonedDateTime utcDateTime = ZonedDateTime.parse(dateString, inputFormatter);
            return utcDateTime.withZoneSameInstant(targetZone).format(outputFormatter);
        } catch (Exception e) {
            return dateString; // Trả về nguyên bản nếu có lỗi parse
        }
    }
}
