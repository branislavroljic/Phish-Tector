package org.unibl.etf.phishtector.response.dmarc;

import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DMARCVerificationResponse {

  private boolean compliant;
  private String domain;
  private String dmarcRecord;
  private boolean recordPublished;
  private boolean validSyntax;
  private Map<String, String> tagValueMap;
  private boolean externalValidationSucceeded;
  private String policyRecordType;
  private boolean multipleRecordsFound;
  private String exceptionMessage;
}
