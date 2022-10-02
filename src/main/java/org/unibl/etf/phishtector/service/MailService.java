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
import org.unibl.etf.phishtector.response.techniknews.IPAnalysisResponse;
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
//    Pattern pattern =
//        Pattern.compile(mailHeaderProperties.getDelimiter() + mailHeaderProperties.getReceivedField());
//    List<String> lines = new ArrayList<>();
//    new BufferedReader(new InputStreamReader(mailFile.getInputStream(), StandardCharsets.UTF_8))
//        .lines()
//        .forEach(lines::add);
//    lines.forEach(l -> System.out.println("= " + l));
    /*MimeMessage mimeMessageObj = new MimeMessage(null, mailFile.getInputStream());

    LinkedList<HashMap<String, String>> receivedChain = new LinkedList<>();
    Enumeration<Header> headers = mimeMessageObj.getAllHeaders();

    Pattern p = Pattern.compile("(?:(Received:)|\\G(?!\\A))" +
        "\\s*(from|by|with|id|via|for|;)" +
        "\\s*(\\S+?(?:\\s+\\S+?)*?)\\s*" +
        "(?=Received:|by|with|id|via|for|;|\\z)");

    while (headers.hasMoreElements()) {
      Header headerField = headers.nextElement();
    //  System.out.println("=" + next.getName() + " : " + next.getValue());
      if (headerField.getName().equals("Received")) {

      }*/

    MimeMessage mimeMessageObj = new MimeMessage(null, mailFile.getInputStream());

    //List<Attachment> attachments = email.getAttachments();

//    Attachment calendar = email.getCalendarBody();
//    Attachment htmlBody = email.getHTMLEmailBody();
//    Attachment plainText = email.getPlainTextEmailBody();
//
//    String to = email.getToEmailHeaderValue();
//    String cc = email.getCCEmailHeaderValue();
//    String from = email.getFromEmailHeaderValue();

    Email email = getEmail(mailFile);
    List<Field> fields = email.getHeader().getFields();

//    if (fields.stream().filter(f -> f.getName().equals("Return-Path")).count() > 1) {
//      System.out.println("Pronadjena vise od dva Return-Path polja, POSSIBLE SPAM MESSAGE");
//    }

    String returnPathDomain = Util.getReturnPathDomain(fields);

    InternetAddress ia = (InternetAddress) mimeMessageObj.getFrom()[0];
    String fromDomain = Util.getDomainFromEmailAddress(ia.getAddress());

    List<Hop> hops = hopsService.parseHopsFromReceivedFields(fields);

    hops.forEach(hop -> hop.setIpAnalysisResponse(ipService.investigateIPAddress(hop)));

    //List<IPAnalysisResponse> ipAnalysisResponses = ipService.investigateIPAddresses(hops);

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
        spfService.testSPF(returnPathDomain, fromDomain, dmarcTagValueMap);

    DKIMVerificationResponse dkimVerificationResponse = dkimService.testDKIM(mailFile,
        dmarcTagValueMap);

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



  /*//TODO ovo ne radi, jer nema veze koji je domen, njega interesuje samo ovaj spf record koji
  // saljem, a tipa za gmail je v=spf1 redirect=_spf.google.com, pa ispadne da ima samo jedan lookup
  private int getNumOfLookups(String domain, String spfRecord) throws IOException, JSONException {
    final String uri = apiProperties.getNetworkcalcUri() + domain;

    RestTemplate restTemplate = new RestTemplate();
    ObjectMapper mapper = new ObjectMapper();
    JSONObject jsonObject = new JSONObject(restTemplate.postForObject(uri,
        new NetworkcalcRequest(spfRecord), String.class));
    return jsonObject.getJSONObject("validation").getInt("total_lookups");
  }*/
}

