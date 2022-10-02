package org.unibl.etf.phishtector.service;

import com.google.common.base.CharMatcher;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import org.apache.james.jspf.core.SPF1Record;
import org.apache.james.jspf.core.exceptions.NeutralException;
import org.apache.james.jspf.core.exceptions.NoneException;
import org.apache.james.jspf.core.exceptions.PermErrorException;
import org.apache.james.jspf.core.impl.DefaultSPF;
import org.apache.james.jspf.core.impl.DefaultTermsFactory;
import org.apache.james.jspf.executor.FutureSPFResult;
import org.apache.james.jspf.parser.RFC4408SPF1Parser;
import org.springframework.stereotype.Service;
import org.unibl.etf.phishtector.config.MailHeaderProperties;
import org.unibl.etf.phishtector.model.SPFTag;
import org.unibl.etf.phishtector.response.spf.SPFVerificationResponse;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

@Service
@RequiredArgsConstructor
public class SPFService {

  private final MailHeaderProperties mailHeaderProperties;

  private static final String SPF_MODIFIER_QUALIFIER = "+";

  public SPFVerificationResponse testSPF(String returnPathDomain,
      String fromDomain, Map<String, String> dmarcTagValueMap) {

    SPFVerificationResponse spfVerificationResponse = new SPFVerificationResponse();
    try {
      List<Record> records = Util.queryRecords(returnPathDomain, Type.TXT);

      long numOfSpfRecords = countNumOfSpfRecords(records);
      String spfRecord = getSpfRecord(records);

      if (spfRecord != null) {

        //TODO skontaj koja IP adresa i koji hostName treba!
        FutureSPFResult futureSPFResult = new DefaultSPF().checkSPF("209.85.220.41",
            "jadranmoon.com"
            , "google.com");

        SPF1Record spf1Record = parseDirectivesAndModifiers(
            spfRecord);
        spfVerificationResponse.setDomain(returnPathDomain);
        spfVerificationResponse.setIpAddress("209.85.220.41");
        spfVerificationResponse.setDirectives(spf1Record.getDirectives().stream()
            .map(d -> new SPFTag(d.getQualifier(), d.getMechanism().toString())).toList());
        spfVerificationResponse.setModifiers(spf1Record.getModifiers().stream()
            .map(m -> new SPFTag(SPFService.SPF_MODIFIER_QUALIFIER, m.toString()))
            .toList());
        spfVerificationResponse.setRecord(spfRecord);
        spfVerificationResponse.setSignatureDomainAligned(
            Util.verifyDomainAlignment(returnPathDomain, fromDomain,
                dmarcTagValueMap.get("aspf")));
        spfVerificationResponse.setAuthenticationResult(futureSPFResult.getResult());
        spfVerificationResponse.setOnlyOneRecord(numOfSpfRecords == 1);
        spfVerificationResponse.setValidSyntax(true);
        spfVerificationResponse.setNoCharsAfterALL(checkForNoCharsAfterAll(spfRecord));
        spfVerificationResponse.setNumOfLookups(futureSPFResult.getSpfSession().getCurrentDepth());
    //    spfVerificationResponse.setValidLength(checkSpfRecordLength(spfRecord));
        spfVerificationResponse.setNoPTRFound(!isPTRFound(spfRecord));
        spfVerificationResponse.setNoAnyPassMechanism(!anyPassMechanismPresent(spfRecord));

      } else {
        return new SPFVerificationResponse();
      }
    } catch (Exception e) {
      spfVerificationResponse.setExceptionMessage(e.getMessage());

    }
    return spfVerificationResponse;
  }

//  public boolean checkSpfAlignment(String from, String returnPath,
//      String dmarcRecord, String dmarcAspfValue) {

//    //TODO ovdje bih mogao provjeriti da li domeni uopste postoje, sa  InetAddress inetAddress = InetAddress.getByName("yahoo.com");
//    InternetDomainName fromDomain = InternetDomainName.from(from);
//    InternetDomainName returnPathDomain = InternetDomainName.from(returnPath);
//    System.out.println("fromDomain.parent().equals(returnPathDomain):  " +
//        fromDomain.parent().equals(returnPathDomain));
//
//    System.out.println("Poredim: " + fromDomain.toString() + " : " + returnPathDomain.toString());
//
//    if (from.equals(returnPath)) {
//      return true;
//    } else if (fromDomain.parent().equals(returnPathDomain) || returnPathDomain
//        .parent().equals(fromDomain)) {
//      if (dmarcRecord == null) {
//        return true;
//      } else {
////        Matcher aspfDmarcMatcher = aspfDmarcPattern.matcher(dmarcRecord);
////        if (!aspfDmarcMatcher.find() || aspfDmarcMatcher.group(1)
////            .startsWith(mailHeaderProperties.getDmarcAspfRelaxed())) {
////          return true;
////        }
//        return !dmarcTagValueMap.containsKey("aspf") || dmarcTagValueMap.get("aspf")
//            .startsWith("r");
//      }
//    }
//    return false;
  // }

  private SPF1Record parseDirectivesAndModifiers(String spfRecord)
      throws PermErrorException, NoneException, NeutralException {
    RFC4408SPF1Parser rfc4408SPF1Parser = new RFC4408SPF1Parser(new DefaultTermsFactory());
    return rfc4408SPF1Parser.parse(spfRecord);
  }

  private boolean checkForNoCharsAfterAll(String spfRecord) {
    Pattern pattern1 = Pattern.compile("[-+?~]?(all)");
    Pattern pattern2 = Pattern.compile("[-+?~]?(all)$");

    return !pattern1.matcher(spfRecord).find() || (
        pattern1.matcher(spfRecord).find() && pattern2.matcher(
            spfRecord).find());

  }

  private boolean anyPassMechanismPresent(String spfRecord) {
    Pattern pattern = Pattern.compile("\\+all$");
    return pattern.matcher(spfRecord).find();
  }

  private long countNumOfSpfRecords(List<Record> records) {

    return records.stream()
        .filter(r -> CharMatcher.is('\"').trimFrom(r.rdataToString())
            .startsWith(mailHeaderProperties.getSpfVersion())).count();
  }

  private String getSpfRecord(List<Record> records) {
    return records.stream()
        .map(r -> CharMatcher.is('\"').trimFrom(r.rdataToString()))
        .filter(r -> r.startsWith(mailHeaderProperties.getSpfVersion())).findFirst()
        .orElse(null);
  }

  //ovo nije tacno, duzina stringa ne smije biti veca od 255, ali SPF record moze
//  private boolean checkSpfRecordLength(String spfRecord) {
//    return spfRecord.length() <= 255;
//  }

  private boolean isPTRFound(String spfRecord) {
    Pattern pattern = Pattern.compile("ptr(:.*)?");
    return pattern.matcher(spfRecord).find();
  }

  private boolean checkSPFSyntax(String spfRecord) {
    Pattern spfSyntaxPattern = Pattern.compile("^v=spf1( +([-+?~]?(all|include:"
        + "(%\\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\\/=_]*\\}|%%|%_|%-|[!-$&-~])*(\\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\\/=_]*\\})|a(:(%\\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\\/=_]*\\}|%%|%_|%-|[!-$&-~])*(\\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\\/=_]*\\}))?((\\/(\\d|1\\d|2\\d|3[0-2]))?(\\/\\/([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8]))?)?|mx(:(%\\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\\/=_]*\\}|%%|%_|%-|[!-$&-~])*(\\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\\/=_]*\\}))?((\\/(\\d|1\\d|2\\d|3[0-2]))?(\\/\\/([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8]))?)?|ptr(:(%\\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\\/=_]*\\}|%%|%_|%-|[!-$&-~])*(\\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\\/=_]*\\}))?|ip4:([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/([0-9]|1[0-9]|2[0-9]|3[0-2]))?|ip6:(::|([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,8}:|([0-9A-Fa-f]{1,4}:){7}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){5}(:[0-9A-Fa-f]{1,4}){1,3}|([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){1,5}|([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){1,6}|[0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){1,7}|:(:[0-9A-Fa-f]{1,4}){1,8}|([0-9A-Fa-f]{1,4}:){6}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){6}:([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){5}:([0-9A-Fa-f]{1,4}:)?([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){4}:([0-9A-Fa-f]{1,4}:){0,2}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){3}:([0-9A-Fa-f]{1,4}:){0,3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){2}:([0-9A-Fa-f]{1,4}:){0,4}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|[0-9A-Fa-f]{1,4}::([0-9A-Fa-f]{1,4}:){0,5}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|::([0-9A-Fa-f]{1,4}:){0,6}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(\\/(\\d{1,2}|10[0-9]|11[0-9]|12[0-8]))?|exists:(%\\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\\/=_]*\\}|%%|%_|%-|[!-$&-~])*(\\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\\/=_]*\\}))|redirect=(%\\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\\/=_]*\\}|%%|%_|%-|[!-$&-~])*(\\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\\/=_]*\\})|exp=(%\\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\\/=_]*\\}|%%|%_|%-|[!-$&-~])*(\\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\\/=_]*\\})|[A-Za-z][-.0-9A-Z_a-z]*=(%\\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\\/=_]*\\}|%%|%_|%-|[!-$&-~])*))* *$");
    return spfSyntaxPattern.matcher(spfRecord).find();

  }

}
