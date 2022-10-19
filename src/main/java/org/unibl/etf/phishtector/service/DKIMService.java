package org.unibl.etf.phishtector.service;

import com.example.dkimapp.DKIMVerifier;
import com.example.dkimapp.exceptions.FailException;
import com.example.dkimapp.response.DKIMVerificationResult;
import com.example.dkimapp.response.FailExceptionResult;
import com.example.dkimapp.tagvalue.SignatureRecord;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.mail.MessagingException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.unibl.etf.phishtector.config.ApiProperties;
import org.unibl.etf.phishtector.response.dkim.DKIMFailExceptionResponse;
import org.unibl.etf.phishtector.response.dkim.DKIMSignatureRecordResponse;
import org.unibl.etf.phishtector.response.dkim.DKIMVerificationResponse;

@Service
@RequiredArgsConstructor
public class DKIMService {

  private final ApiProperties apiProperties;
  private final ModelMapper modelMapper;

  public DKIMVerificationResponse testDKIM(MultipartFile mailFile,
      Map<String, String> dmarcTagValueMap) throws IOException, MessagingException {

    List<DKIMSignatureRecordResponse> dkimSignatureRecordResponses = null;
    List<DKIMFailExceptionResponse> dkimFailExceptionResponses = null;
    DKIMVerificationResult dkimVerificationResult = null;
    try {
      dkimVerificationResult =
          new DKIMVerifier().verify(mailFile.getInputStream());

      InternetAddress ia = (InternetAddress) new MimeMessage(null,
          mailFile.getInputStream()).getFrom()[0];
      String fromDomain = Util.getDomainFromEmailAddress(ia.getAddress());

      dkimSignatureRecordResponses = new ArrayList<>();
      for (SignatureRecord signatureRecord : dkimVerificationResult.getSignatureRecords()) {
        DKIMSignatureRecordResponse signatureRecordResponse = modelMapper.map(signatureRecord,
            DKIMSignatureRecordResponse.class);
        signatureRecordResponse.setDkimSignatureAligned(Util.verifyDomainAlignment(fromDomain,
            (String) signatureRecord.getTagValues().get("d"), dmarcTagValueMap.get("adkim")));
        dkimSignatureRecordResponses.add(signatureRecordResponse);
      }

      dkimFailExceptionResponses = new ArrayList<>();
      for (FailExceptionResult failExceptionResult :
          dkimVerificationResult.getExceptionResponses()) {
        DKIMSignatureRecordResponse signatureRecordResponse = modelMapper.map(
            failExceptionResult.getSignatureRecord(),
            DKIMSignatureRecordResponse.class);
        signatureRecordResponse.setDkimSignatureAligned(Util.verifyDomainAlignment(fromDomain,
            (String) failExceptionResult.getSignatureRecord().getTagValues().get("d"),
            dmarcTagValueMap.get("adkim")));
        dkimFailExceptionResponses.add(new DKIMFailExceptionResponse(signatureRecordResponse,
            failExceptionResult.getMessage()));
      }
    } catch (FailException e) {
      return new DKIMVerificationResponse(null, null, e.getMessage());
    }
    return DKIMVerificationResponse.builder()
        .signatureRecords(dkimSignatureRecordResponses)
        .exceptionResponses(dkimFailExceptionResponses).exceptionMessage(null).build();

  }


}
