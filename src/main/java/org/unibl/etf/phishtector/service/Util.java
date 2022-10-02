package org.unibl.etf.phishtector.service;

import com.google.common.net.InternetDomainName;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.apache.james.mime4j.stream.Field;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TextParseException;


public class Util {

  public static List<Record> queryRecords(String domain, int lookupType)
      throws UnknownHostException, TextParseException {
    Lookup lookup = new Lookup(Name.fromString(domain), lookupType);
    Resolver resolver = new SimpleResolver();
    lookup.setResolver(resolver);
    Record[] records = lookup.run();
    if (records != null && records.length > 0) {
      return Arrays.asList(records);
    }
    return Collections.emptyList();
  }

  public static String getDomainFromEmailAddress(String emailAddress) {
    return emailAddress.substring(emailAddress.indexOf("@") + 1);
  }

  public static boolean verifyDomainAlignment(String domain1, String domain2, String dmarcMode) {
    InternetDomainName internetDomain1 = InternetDomainName.from(domain1);
    InternetDomainName internetDomain2 = InternetDomainName.from(domain2);

    if (domain1.equals(domain2)) {
      return true;
    } else if (internetDomain1.parent().equals(internetDomain2) || internetDomain2
        .parent().equals(internetDomain1)) {
      return dmarcMode == null || dmarcMode.startsWith("r");
    }
    return false;
  }

  public static String getReturnPathDomain(List<Field> fields) {

    Field returnPathField =
        fields.stream().filter(f -> f.getName().equals("Return-Path")).findFirst().orElse(null);
    if (returnPathField != null) {
      return Util.getDomainFromEmailAddress(
          returnPathField.getBody().substring(returnPathField.getBody().indexOf("<") + 1,
              returnPathField.getBody().indexOf(">")));
    }
    return null;
  }
}
