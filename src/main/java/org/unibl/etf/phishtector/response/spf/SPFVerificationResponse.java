package org.unibl.etf.phishtector.response.spf;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.james.jspf.core.SPF1Record;
import org.apache.james.jspf.terms.Directive;
import org.unibl.etf.phishtector.model.SPFTag;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SPFVerificationResponse {

//  //discard records that do not begin with a version section of exactly  "v=spf1".
//  private boolean found;

  private String domain;
  private String ipAddress;
  private String record;
  private List<SPFTag> directives;
  private List<SPFTag> modifiers;
  private boolean signatureDomainAligned;

  private String authenticationResult;
  // If the resultant record set includes more than one record, check_host() produces the "permerror" result.
  private boolean onlyOneRecord;
  //    syntax of the record is
//   validated first, and if there are any syntax errors anywhere in the
//   record, check_host() returns immediately with the result "permerror",
//   without further interpretation or evaluation.
  private boolean validSyntax;

  private boolean noCharsAfterALL;
  //SPF implementations MUST limit the total number of those terms to 10 during SPF evaluation
  private int numOfLookups;
  //It's not advised to use PTR as this is a deprecated one, and several senders may ignore the SPF record when this method is used
  private boolean noPTRFound;

  //Using +all is discouraged
  private boolean noAnyPassMechanism;

  private String exceptionMessage;
}
