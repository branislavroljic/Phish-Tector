package org.unibl.etf.phishtector.response.dkim;

import java.util.Map;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class DKIMSignatureRecordResponse {

  private  Map<String, CharSequence> tagValues;
  private  Map<String, CharSequence> defaults;
  private Map<String, CharSequence> publicRecordTagValue;
  private boolean validRecordSyntax;
  private boolean publicKeyPresent;
  private boolean validSignatureSyntax;
  private boolean noDuplicateTags;
  private boolean signatureNotExpired;
  private boolean bodyHashVerified;
  private String stringRepresentation;
  private Integer signatureTimestamp;
  private boolean dkimSignatureAligned;

}
