package org.unibl.etf.phishtector.response.dkim;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DKIMFailExceptionResponse {

  private DKIMSignatureRecordResponse signatureRecord;
  private String message;
}
