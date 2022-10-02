package org.unibl.etf.phishtector.service;

import de.malkusch.whoisServerList.publicSuffixList.PublicSuffixList;
import de.malkusch.whoisServerList.publicSuffixList.PublicSuffixListFactory;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.unibl.etf.phishtector.config.MailHeaderProperties;
import org.unibl.etf.phishtector.exception.HttpException;
import org.unibl.etf.phishtector.exception.MultipleRecordsFoundException;
import org.unibl.etf.phishtector.exception.NoRecordFoundException;
import org.unibl.etf.phishtector.exception.SyntaxException;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

@Service
@RequiredArgsConstructor
public class DmarcService {

  private final MailHeaderProperties mailHeaderProperties;
  private final List<String> mandatoryTags = List.of("p");

  private final String DMARC_VERSION = "v=DMARC1";
  private final String DMARC_VERSION_SEMICOLON = "v=DMARC1;";
  private final String REPORT_DMARC_PREFIX = "_report._dmarc";

  private final String DMARC_VERSION_REGEX = "^(v=DMARC1;?)";
  //the ending of regex => ;? - semicolon is present except for the last term
  private final String DMARC_TERM_REGEX = "(adikm|aspf|fo|p|pct|rf|ri|rua|ruf|sp)=([\\w.:@/+!,_\\- "
      + "]+);?";

  Pattern dmarcTermPattern = Pattern.compile(DMARC_TERM_REGEX);

  Pattern dmarcVersionRegex = Pattern.compile(DMARC_VERSION_REGEX);

  public String getDmarcRecord(String fromDomain) throws UnknownHostException, TextParseException {
    Lookup lookup = new Lookup(Name.fromString(mailHeaderProperties.getDmarcPrefix() + fromDomain),
        Type.TXT);
    lookup.setResolver(new SimpleResolver());
    Record[] records = lookup.run();
    String dmarcRecord = null;

    if (records != null && records.length != 0) {
      for (Record rec : records) {
        if (rec.rdataToString().contains("v=DMARC1")) {
          dmarcRecord = rec.rdataToString().replaceAll("^\"|\"$", "");
        }
      }
    } else {
      throw new NoRecordFoundException("DMARC record not found!");
    }

    return dmarcRecord;
  }

  public Map<String, String> parse(String dmarcRecord) {

    Matcher versionMatcher = dmarcVersionRegex.matcher(dmarcRecord);
    // check the version "header"
//    if (!dmarcRecord.startsWith(DMARC_VERSION_SEMICOLON + " ") && !dmarcRecord.equalsIgnoreCase(
//        DMARC_VERSION)) {
//      throw new SyntaxException(
//          "Empty DMARC record");
//    }

    if (!versionMatcher.find()) {
      throw new SyntaxException(
          "Empty DMARC record");
    }
    Map<String, String> tagValueMap = new HashMap<>();

    // extract terms
    String[] terms = dmarcRecord.replaceFirst(
        versionMatcher.group(1), "").split(" ");

    // cycle terms
    for (String term : terms) {
      if (term.length() > 0) {
        Matcher dmarcTermMatcher = dmarcTermPattern.matcher(term);
        if (!dmarcTermMatcher.matches()) {
          throw new SyntaxException("Term [" + term
              + "] is not syntactically valid: ");
        }

        if (tagValueMap.containsKey(dmarcTermMatcher.group(1))) {
          throw new SyntaxException("DMARC records contains duplicate tags");
        }
        tagValueMap.put(dmarcTermMatcher.group(1), dmarcTermMatcher.group(2));
      }
    }

    if (!mandatoryTagsPresent(tagValueMap)) {
      throw new SyntaxException("Mandatory tags are not present!");
    }

    return tagValueMap;
  }

  public void verifyDmarcExternalDestinations(String fromDomain,
      Map<String, String> tagValueMap) throws UnknownHostException, TextParseException {

    List<String> destinationHosts = new ArrayList<>();
//     Extract the host portion of the authority component of the URI.
//       Call this the "destination host", as it refers to a Report
//       Receiver
    if (tagValueMap.containsKey("rua")) {
      parseDestinationHosts(destinationHosts, tagValueMap.get("rua"), fromDomain);
    }
    if (tagValueMap.containsKey("ruf")) {
      parseDestinationHosts(destinationHosts, tagValueMap.get("ruf"), fromDomain);
    }


    for (String domainToCheck : destinationHosts) {
//      Prepend the string "_report._dmarc".
      domainToCheck = REPORT_DMARC_PREFIX + "." + domainToCheck;
//      Prepend the domain name from which the policy was retrieved, after conversion to an A-label if needed.
      domainToCheck = fromDomain + "." + domainToCheck;

      boolean authorizedByReportReceiver = checkIfAuthorizedByReportReceiver(domainToCheck);
      if (!authorizedByReportReceiver) {
        throw new HttpException("Domain: " + fromDomain + " is not authorized by Report Receiver:"
            + " " + domainToCheck);
      }
    }
  }

  private boolean checkIfAuthorizedByReportReceiver(String domainToCheck)
      throws UnknownHostException, TextParseException {
    List<Record> records = Util.queryRecords(domainToCheck, Type.TXT);
    if (records != null) {
      for (Record record : records) {

        String recordAsString = record.rdataToString().replaceAll("^\"|\"$", "");
        Matcher versionMatcher = dmarcVersionRegex.matcher(recordAsString);
        if (versionMatcher.find()) {
          return true;
        }
      }
    }
    return false;
  }

  public String getDMARCRecordPolicy(String fromDomain)
      throws UnknownHostException, TextParseException {

    Map<String, String> tagValueMap = parse(getDMARCRecordForPolicyDiscovery(fromDomain));
    if (tagValueMap.containsKey("p")) {
      return tagValueMap.get("p");
    } else if (tagValueMap.containsKey("rua")) {
      List<String> destinationHosts = new ArrayList<>();
      parseDestinationHosts(destinationHosts, tagValueMap.get("rua"), fromDomain);

      for (String domainToCheck : destinationHosts) {
//      Prepend the string "_report._dmarc".
        domainToCheck = REPORT_DMARC_PREFIX + "." + domainToCheck;
//      Prepend the domain name from which the policy was retrieved, after conversion to an A-label if needed.
        domainToCheck = fromDomain + "." + domainToCheck;

        System.out.println("domainTOCHeck: " + domainToCheck);

        boolean authorizedByReportReceiver = checkIfAuthorizedByReportReceiver(domainToCheck);
        if (!authorizedByReportReceiver) {
          throw new HttpException("Domain: " + fromDomain + " is not authorized by Report Receiver:"
              + " " + domainToCheck + ". DMARC Policy check terminated!");
        } else {
          return "none";
        }
      }
    }
    throw new HttpException("DMARC Policy check terminated! Cannot find 'p' tag or 'rua' tag");
  }

  private String getDMARCRecordForPolicyDiscovery(String fromDomain)
      throws UnknownHostException, TextParseException {
    //Query the DNS for a DMARC record on the RFC5322.From domain found in step 1; depending on the outcome:
    List<Record> records = Util.queryRecords(mailHeaderProperties.getDmarcPrefix() + fromDomain,
        Type.TXT);
    if (records != null) {
      List<Record> dmarcRecords =
          records.stream().filter(
                  record -> record.rdataToString().replaceAll("^\"|\"$", "").startsWith(DMARC_VERSION))
              .toList();
      if (dmarcRecords.size() > 1) {
//        if multiple DMARC records are found, policy discovery terminates and DMARC processing is not applied to this message;
        throw new MultipleRecordsFoundException("Multiple DMARC records found!");
      } else {
//        if only 1 DMARC record is found, the policy in the record is returned;
        return dmarcRecords.get(0).rdataToString().replaceAll("^\"|\"$", "");
      }
    } else {
      //if no DMARC record is found query the DNS for a DMARC record on the organizational domain
      // of the RFC5322.From domain, if the 2 domains are different; depending on the outcome

      PublicSuffixListFactory factory = new PublicSuffixListFactory();
      PublicSuffixList suffixList = factory.build();
      String organizationalDomain = suffixList.getRegistrableDomain(fromDomain);
      if (!organizationalDomain.equals(fromDomain)) {

        List<Record> orgDomainRecords =
            Util.queryRecords(mailHeaderProperties.getDmarcPrefix() + organizationalDomain,
                Type.TXT);

        if (orgDomainRecords != null) {
          return orgDomainRecords.stream().filter(r -> r.rdataToString().replaceAll("^\"|\"$",
                  "").startsWith(DMARC_VERSION)).findAny()
              .orElseThrow(() -> new NoRecordFoundException("No DMARC record found!"))
              .rdataToString().replaceAll("^\"|\"$",
                  "");
        } else {
          throw new NoRecordFoundException("No DMARC record found!");
        }
      } else {
        throw new NoRecordFoundException("No DMARC record found!");
      }
    }
  }

  private void parseDestinationHosts(List<String> domainsToCheck, String uriRecords,
      String fromDomain) {
    //uri records are comma separated values
    for (String uri : uriRecords.split(",")) {
      String domain = uri.replace("mailto:", "").split("@")[1];
      if (!domain.equals(fromDomain)) {
        domainsToCheck.add(domain);
      }
    }
  }

  private boolean mandatoryTagsPresent(Map<String, String> tagValueMap) {
    for (String tag : mandatoryTags) {
      if (!tagValueMap.containsKey(tag)) {
        return false;
      }
    }
    return true;
  }
}
