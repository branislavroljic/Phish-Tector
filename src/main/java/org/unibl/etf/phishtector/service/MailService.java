package org.unibl.etf.phishtector.service;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.mail.MessagingException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.apache.james.mime4j.MimeException;
import org.apache.james.mime4j.codec.DecodeMonitor;
import org.apache.james.mime4j.message.DefaultBodyDescriptorBuilder;
import org.apache.james.mime4j.parser.MimeStreamParser;
import org.apache.james.mime4j.stream.BodyDescriptorBuilder;
import org.apache.james.mime4j.stream.Field;
import org.apache.james.mime4j.stream.MimeConfig;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.unibl.etf.phishtector.exception.HttpException;
import org.unibl.etf.phishtector.exception.MultipleRecordsFoundException;
import org.unibl.etf.phishtector.model.Hop;
import org.unibl.etf.phishtector.response.MailAnalysisResponse;
import org.unibl.etf.phishtector.response.dkim.DKIMVerificationResponse;
import org.unibl.etf.phishtector.response.dmarc.DMARCVerificationResponse;
import org.unibl.etf.phishtector.response.spf.SPFVerificationResponse;
import org.unibl.etf.phishtector.response.url.URLResponse;
import tech.blueglacier.email.Email;
import tech.blueglacier.parser.CustomContentHandler;

@Service
@RequiredArgsConstructor
public class MailService {

  private final DmarcService dmarcService;
  private final DKIMService dkimService;
  private final SPFService spfService;
  private final URLService urlService;
  private final HopsService hopsService;
  private final IPService ipService;


  public MailAnalysisResponse analyzeMail(MultipartFile mailFile)
      throws IOException, MimeException, MessagingException {

    MimeMessage mimeMessageObj = new MimeMessage(null, mailFile.getInputStream());

    //List<Attachment> attachments = email.getAttachments();

    Email email = getEmail(mailFile);
    List<Field> fields = email.getHeader().getFields();

    String returnPathDomain = Util.getReturnPathDomain(fields);

    InternetAddress ia = (InternetAddress) mimeMessageObj.getFrom()[0];
    String fromDomain = Util.getDomainFromEmailAddress(ia.getAddress());

    List<Hop> hops = hopsService.parseHopsFromReceivedFields(fields);

    hopsService.investigateHops(hops);

    DMARCVerificationResponse dmarcVerificationResponse = new DMARCVerificationResponse();
    Map<String, String> dmarcTagValueMap = new HashMap<>();
    try {
      String dmarcRecord = dmarcService.getDmarcRecord(fromDomain);
      dmarcVerificationResponse.setDomain(fromDomain);
      dmarcVerificationResponse.setRecordPublished(true);
      dmarcVerificationResponse.setDmarcRecord(dmarcRecord);

      dmarcTagValueMap = dmarcService.parse(dmarcRecord);
      dmarcVerificationResponse.setTagValueMap(dmarcTagValueMap);
      dmarcVerificationResponse.setValidSyntax(true);

      dmarcService.verifyDmarcExternalDestinations(fromDomain,
          dmarcTagValueMap);
      dmarcVerificationResponse.setExternalValidationSucceeded(true);

      String policyRecordType = dmarcService.getDMARCRecordPolicy(fromDomain);
      dmarcVerificationResponse.setPolicyRecordType(policyRecordType);
    } catch (Exception e) {
      if (e instanceof MultipleRecordsFoundException) {
        dmarcVerificationResponse.setMultipleRecordsFound(true);
      }
      if (e instanceof HttpException httpException) {
        dmarcVerificationResponse.setExceptionMessage(httpException.getData().toString());
      } else {
        dmarcVerificationResponse.setExceptionMessage("An error occurred while analysing DMARC"
            + " record");
      }
      e.printStackTrace();
    }

    SPFVerificationResponse spfVerificationResponse =
        spfService.testSPF(returnPathDomain, fromDomain, dmarcTagValueMap, fields);

    DKIMVerificationResponse dkimVerificationResponse = dkimService.testDKIM(mailFile,
        dmarcTagValueMap);

    dmarcVerificationResponse.setCompliant(
        dmarcService.checkDMARCCompliance(spfVerificationResponse, dkimVerificationResponse));
    URLResponse urlResponse = urlService.analyzeMailUrls(mimeMessageObj);

    return MailAnalysisResponse.builder()
        .hops(hops)
        .dmarcVerificationResponse(dmarcVerificationResponse)
        .spfVerificationResponse(spfVerificationResponse)
        .dkimVerificationResponse(dkimVerificationResponse).urlResponse(urlResponse).build();
  }

  private Email getEmail(MultipartFile mailFile) throws IOException, MimeException {
    CustomContentHandler contentHandler = new CustomContentHandler();

    MimeConfig mime4jParserConfig = MimeConfig.DEFAULT;
    BodyDescriptorBuilder bodyDescriptorBuilder = new DefaultBodyDescriptorBuilder();
    MimeStreamParser mime4jParser = new MimeStreamParser(mime4jParserConfig, DecodeMonitor.SILENT,
        bodyDescriptorBuilder);
    mime4jParser.setContentDecoding(true);
    mime4jParser.setContentHandler(contentHandler);
    mime4jParser.parse(mailFile.getInputStream());
    return contentHandler.getEmail();
  }

}

