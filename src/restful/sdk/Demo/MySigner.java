package restful.sdk.Demo;

import API.Utils;
import Model.Enum.HashAlgorithmOID;
import Model.Enum.SignAlgo;
import Model.Request.DocumentDigests;
import vn.mobileid.openpdf.*;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.cert.Certificate;
import java.text.SimpleDateFormat;
import java.util.*;

public class MySigner {

    private final String credentialID;
    private final String sad;
    private final List<Certificate> certChain;

    public MySigner(String credentialID, String sad, List<Certificate> certChain) {
        this.credentialID = credentialID;
        this.sad = sad;
        this.certChain = certChain;
    }

    public byte[] signPdf(byte[] filePdf, byte[] image) throws Exception {
        Date now = new Date();
        SimpleDateFormat formatter = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
        String formattedDate = formatter.format(now);

        // setup PDF object
        PDFSignObject pdf = new PDFSignObject();
        pdf.setDocument(filePdf);
        pdf.setPageNo("1");
        pdf.setRectangle(new Rectangle(100, 100, 300, 200));
        pdf.setFontSize((float) 12.5);
        pdf.setReason("Ký duyệt");
        pdf.setLocation("HCM");
        pdf.setSigningTime(now);
        pdf.setDateFormat(formattedDate);
        pdf.setSignerInformation("Ký bởi: {signby}"
                + "\nLý do: {reason}"
                + "\nKý ngày: {date}"
                + "\nNơi ký: {location}");

        SignatureImage signatureImage = new SignatureImage(image);
        signatureImage.scaleToFit(50, 50);
        signatureImage.setImageAligment(ImageAligment.RIGHT_BOTTOM);
        pdf.setSignatureImage(signatureImage);

        List<PDFSignObject> dataToBeSigns = new ArrayList<>();
        dataToBeSigns.add(pdf);

        // bước hash
        PDFSigner signer = new PDFSigner();
        PDFSignerResult pdfSignerResult = signer.initSign(dataToBeSigns, certChain);

        List<byte[]> hashList = pdfSignerResult.getHashesList();
        DocumentDigests doc = new DocumentDigests();
        doc.hashAlgorithmOID = HashAlgorithmOID.SHA_256;
        doc.hashes = new ArrayList<>();
        for (byte[] h : hashList) {
            doc.hashes.add(h);
        }

        // ký hash
        List<byte[]> signatures = MainDemo.crt.signHash(credentialID, doc, SignAlgo.RSA, sad);

        PDFSignerResult finalSign = signer.finalSign(pdfSignerResult.getTemporalDatas(), signatures);
        return finalSign.getSignedDocuments().get(0); // trả về file PDF đã ký
    }
}
